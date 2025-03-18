#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>  // THIS IS THE CRUCIAL ADDITION
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>


#define ETH_HDRLEN 14
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define TIMEOUT_SEC 2

struct arp_packet {
    struct ether_header eth_header;
    struct ether_arp arp_payload;
};

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int get_interface_info(const char *ifname, struct in_addr *ip_addr, struct ether_addr *mac_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) die("socket");
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) die("ioctl SIOCGIFADDR");
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    ip_addr->s_addr = ipaddr->sin_addr.s_addr;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) die("ioctl SIOCGIFHWADDR");
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    close(fd);
    return 0;
}

void send_arp_request(int sockfd, const char *ifname, struct in_addr target_ip, struct ether_addr src_mac, struct in_addr src_ip) {
    struct arp_packet pkt;
    
    // Ethernet header
    memset(pkt.eth_header.ether_dhost, 0xff, ETH_ALEN);
    memcpy(pkt.eth_header.ether_shost, src_mac.ether_addr_octet, ETH_ALEN);
    pkt.eth_header.ether_type = htons(ETHERTYPE_ARP);

    // ARP payload
    pkt.arp_payload.arp_hrd = htons(ARPHRD_ETHER);
    pkt.arp_payload.arp_pro = htons(ETHERTYPE_IP);
    pkt.arp_payload.arp_hln = ETH_ALEN;
    pkt.arp_payload.arp_pln = 4;
    pkt.arp_payload.arp_op = htons(ARP_REQUEST);
    
    memcpy(pkt.arp_payload.arp_sha, src_mac.ether_addr_octet, ETH_ALEN);
    memcpy(pkt.arp_payload.arp_spa, &src_ip.s_addr, 4);
    memset(pkt.arp_payload.arp_tha, 0x00, ETH_ALEN);
    memcpy(pkt.arp_payload.arp_tpa, &target_ip.s_addr, 4);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(ifname);
    sa.sll_halen = ETH_ALEN;
    memset(sa.sll_addr, 0xff, ETH_ALEN);

    if (sendto(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        die("sendto");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <MAC>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct ether_addr target_mac;
    if (ether_aton_r(argv[2], &target_mac) == NULL) {
        fprintf(stderr, "Invalid MAC address format\n");
        exit(EXIT_FAILURE);
    }

    struct in_addr src_ip;
    struct ether_addr src_mac;
    get_interface_info(argv[1], &src_ip, &src_mac);

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) die("socket");

    printf("Scanning network...\n");
    for (int i = 1; i < 255; i++) {
        struct in_addr target_ip;
        target_ip.s_addr = src_ip.s_addr & htonl(0xFFFFFF00);
        target_ip.s_addr |= htonl(i);
        send_arp_request(sockfd, argv[1], target_ip, src_mac, src_ip);
    }

    printf("Listening for ARP responses...\n");
    struct timeval tv = {TIMEOUT_SEC, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        unsigned char buffer[ETH_FRAME_LEN];
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) break;

        struct ether_header *eth = (struct ether_header *)buffer;
        if (ntohs(eth->ether_type) != ETHERTYPE_ARP) continue;

        struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
        if (ntohs(arp->arp_op) != ARP_REPLY) continue;

        if (memcmp(arp->arp_sha, target_mac.ether_addr_octet, ETH_ALEN) == 0) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, ip_str, INET_ADDRSTRLEN);
            printf("\nFound IP: %s\n", ip_str);
            close(sockfd);
            exit(EXIT_SUCCESS);
        }
    }

    close(sockfd);
    fprintf(stderr, "MAC address not found on network\n");
    exit(EXIT_FAILURE);
}
