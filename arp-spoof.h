#ifndef ARP_SPOOF_H
#define ARP_SPOOF_H

#include <stdint.h>
#include <pcap.h>
#include "struct_hdr.h" 

typedef struct {
    uint32_t sender_ip;
    Mac sender_mac;
    uint32_t target_ip;
    Mac target_mac;
} Flow;

typedef struct FlowNode {
    Flow flow;
    struct FlowNode* next;
} FlowNode;

FlowNode* create_node(const Flow* flow);
void append_node(FlowNode** head, FlowNode** tail, FlowNode* node);
void free_list(FlowNode* head);
void send_attack_flow(pcap_t* handle, const Mac* my_mac, FlowNode* head);

#endif 