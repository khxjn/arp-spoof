#include "send-arp.h"
#include "arp-spoof.h"
#include <stdlib.h> 

FlowNode* create_node(const Flow* flow) {
    FlowNode* node = (FlowNode*)malloc(sizeof(FlowNode));
    if (node == NULL) return NULL;

    node->flow = *flow;
    node->next = NULL;
    return node;
}

void append_node(FlowNode** head, FlowNode** tail, FlowNode* node) {
    if (*head == NULL) {
        *head = node;
        *tail = node;
        return;
    }

    (*tail)->next = node;
    *tail = node;
}

void free_list(FlowNode* head) {
    FlowNode* cur = head;
    while (cur != NULL) {
        FlowNode* next = cur->next;
        free(cur);
        cur = next;
    }
}

void send_attack_flow(pcap_t* handle, const Mac* my_mac, FlowNode* head) {
    FlowNode* cur = head;
    while (cur != NULL) {
        send_attack(handle, my_mac, &cur->flow); 
        cur = cur->next;
    }
}
