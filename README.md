# arp2ip - Resolve IP to MAC Address

# Overview
arp2ip is a lightweight script that resolves an IP address to its MAC address. Unlike the traditional `arp -a` command, this tool always scans the network instead of relying on cached ARP entries.

Unlike other scripts that scan all networks using grep to find a single MAC address (which can be slow), `arp2ip` provides a faster and more efficient approach.


## Installation

### Dependencies
Before compiling, ensure you have the following dependencies installed:

### Linux headers
GCC (GNU Compiler Collection)
musl-dev or glibc (for standard C library support)
Install Dependencies on Alpine Linux

```
apk add musl-dev gcc linux-headers
```

### Compilation:
```
gcc -Wall -Wextra arp2ip.c -o arp2ip
```

```
./arp2ip <IF> <IP_ADDRESS>
```
