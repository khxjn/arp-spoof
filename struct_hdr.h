#ifndef STRUCT_HDR_H
#define STRUCT_HDR_H

#include <stdint.h>

#pragma pack(push, 1)
typedef struct{
	uint8_t mac[6];
} Mac;

typedef struct {
    Mac dmac;
    Mac smac; 
    uint16_t type;  
} Eth_hdr;

typedef struct {
    uint16_t htype;     // Hardware Type (Ethernet == 1)
    uint16_t ptype;     // Protocol Type (IPv4 == 0x0800)
    uint8_t hlen;       // Hardware Length (Ehternet == 6)
    uint8_t plen;       // Protocol Length (Ipv4 == 4)
    uint16_t op;        // Operation (1 == request, 2 == reply)
    Mac smac;    		// Sender MAC 
    uint32_t sip;       // Sender IP
    Mac tmac;    		// Target MAC
    uint32_t tip;       // Target IP
} Arp_hdr;

typedef struct {
	uint8_t ip_hl;				// Version(4) + IHL(4)
	uint8_t tos;				// Type of Service
	uint16_t ip_tot_len;		// IP Datagram Total length
	uint16_t identification;	// Identification
	uint16_t frag_offset;		// IP flags(3) + Fragment offset(13)
	uint8_t ttl;				// Time To Live
	uint8_t protocol;			// Protocol
	uint16_t ip_checksum;		// Header Checksum
	uint32_t sip;			// Source Address
	uint32_t dip;			// Destination Address
} Ipv4_hdr;

typedef struct {
	uint16_t tcp_src;			// Source Port
	uint16_t tcp_dst;			// Destionation Port
	uint32_t seq_num;			// Sequence Number
	uint32_t ack_num;			// Acknowledgement Number
	uint8_t tcp_hl;				// Offset(4) + Reserved(4)
	uint8_t tcp_flags;			// TCP Flags
	uint16_t window;			// Window
	uint16_t tcp_checksum;		// Checksum
	uint16_t urg_ptr;			// Urgent Pointer
} Tcp_hdr;
#pragma pack(pop)

#endif