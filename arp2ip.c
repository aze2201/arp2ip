#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>

// Structure combining Ethernet header and ARP payload.
struct arp_packet {
    struct ether_header eth;
    struct ether_arp arp;
};

// Parse MAC address string "xx:xx:xx:xx:xx:xx" into a 6-byte array.
int parse_mac(const char *mac_str, unsigned char *mac) {
    int values[6];
    if (6 == sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5])) {
        for (int i = 0; i < 6; ++i)
            mac[i] = (unsigned char) values[i];
        return 0;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    if(argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <MAC address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Use the first argument as the interface and the second as the target MAC.
    const char *interface = argv[1];
    const char *target_mac_str = argv[2];

    unsigned char target_mac[6];
    if(parse_mac(target_mac_str, target_mac) < 0) {
        fprintf(stderr, "Invalid MAC address format.\n");
        exit(EXIT_FAILURE);
    }

    // Create a raw socket for ARP (requires root privileges).
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set up the interface requests.
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    // Get the interface index.
    if(ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    int ifindex = ifr.ifr_ifindex;

    // Get local MAC address.
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    unsigned char local_mac[6];
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);

    // Get local IP address.
    if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    uint32_t local_ip = ipaddr->sin_addr.s_addr;

    // Get subnet mask.
    if(ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in *nm = (struct sockaddr_in *)&ifr.ifr_netmask;
    uint32_t netmask = nm->sin_addr.s_addr;

    // Calculate network and broadcast addresses.
    uint32_t network = local_ip & netmask;
    uint32_t broadcast = network | ~netmask;

    printf("Interface: %s\n", interface);
    printf("Local IP: %s\n", inet_ntoa(*(struct in_addr *)&local_ip));
    printf("Network: %s\n", inet_ntoa(*(struct in_addr *)&network));
    printf("Broadcast: %s\n", inet_ntoa(*(struct in_addr *)&broadcast));

    // Set up the destination address for sending ARP requests.
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_halen = ETH_ALEN;
    memset(socket_address.sll_addr, 0xff, 6);  // Broadcast address.

    // Prepare the ARP request packet.
    struct arp_packet packet;
    memset(&packet, 0, sizeof(packet));

    // Ethernet header: destination is broadcast, source is local MAC.
    memset(packet.eth.ether_dhost, 0xff, 6);
    memcpy(packet.eth.ether_shost, local_mac, 6);
    packet.eth.ether_type = htons(ETH_P_ARP);

    // ARP header.
    packet.arp.arp_hrd = htons(ARPHRD_ETHER);
    packet.arp.arp_pro = htons(ETHERTYPE_IP);
    packet.arp.arp_hln = 6;
    packet.arp.arp_pln = 4;
    packet.arp.arp_op  = htons(ARPOP_REQUEST);
    memcpy(packet.arp.arp_sha, local_mac, 6);
    memcpy(packet.arp.arp_spa, &local_ip, 4);
    memset(packet.arp.arp_tha, 0x00, 6);

    // --- Phase 1: Send ARP requests to all hosts in the subnet ---
    uint32_t ip;
    for(ip = ntohl(network) + 1; ip < ntohl(broadcast); ip++) {
        uint32_t target_ip = htonl(ip);
        memcpy(packet.arp.arp_tpa, &target_ip, 4);
        if(sendto(sockfd, &packet, sizeof(packet), 0,
                  (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
            perror("sendto");
        }
        // Optionally add a short sleep (e.g., usleep(1000)) if needed.
    }

    // --- Phase 2: Listen for ARP replies ---
    fd_set readfds;
    struct timeval timeout;
    time_t start_time = time(NULL);
    int found = 0;
    while(time(NULL) - start_time < 3) {  // Wait up to 3 seconds.
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int ret = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        if(ret > 0 && FD_ISSET(sockfd, &readfds)) {
            unsigned char buf[60];
            ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
            if(n < 0)
                continue;
            struct ether_header *recv_eth = (struct ether_header *)buf;
            if(ntohs(recv_eth->ether_type) == ETH_P_ARP) {
                struct ether_arp *recv_arp = (struct ether_arp *)(buf + sizeof(struct ether_header));
                if(ntohs(recv_arp->ea_hdr.ar_op) == ARPOP_REPLY) {
                    // Check if the sender MAC in the reply matches the target.
                    if(memcmp(recv_arp->arp_sha, target_mac, 6) == 0) {
                        struct in_addr found_ip;
                        memcpy(&found_ip, recv_arp->arp_spa, 4);
                        printf("Found target MAC %s at IP: %s\n", target_mac_str, inet_ntoa(found_ip));
                        found = 1;
                        break;
                    }
                }
            }
        }
    }

    if(!found)
        printf("MAC address %s not found in the local network.\n", target_mac_str);

    close(sockfd);
    return 0;
}
