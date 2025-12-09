#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <pcap.h>

// Protocol type enumeration
typedef enum {
    PROTO_UNKNOWN,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_ARP,
    PROTO_IPV4,
    PROTO_IPV6
} protocol_type_t;

// Parsed packet information
typedef struct {
    // Layer 2 (Ethernet)
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ethertype;
    
    // Layer 3 (IP/ARP)
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint8_t protocol;
    int ip_version;
    
    // IPv4 specific
    uint8_t ttl;
    uint16_t ip_id;
    uint16_t total_length;
    uint16_t ip_header_length;
    uint16_t flags;
    
    // IPv6 specific
    uint8_t hop_limit;
    uint8_t traffic_class;
    uint32_t flow_label;
    uint16_t ipv6_payload_length;
    
    // ARP specific
    uint16_t arp_opcode;
    uint8_t arp_sha[6];
    uint8_t arp_tha[6];
    char arp_spa[INET_ADDRSTRLEN];
    char arp_tpa[INET_ADDRSTRLEN];
    uint16_t arp_htype;
    uint16_t arp_ptype;
    uint8_t arp_hlen;
    uint8_t arp_plen;
    
    // Layer 4 (TCP/UDP)
    uint16_t src_port;
    uint16_t dst_port;
    
    // TCP specific
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t tcp_flags;
    uint16_t window_size;
    uint16_t tcp_checksum;
    uint16_t tcp_header_length;
    
    // UDP specific
    uint16_t udp_length;
    uint16_t udp_checksum;
    
    // Layer 7 (Payload)
    const uint8_t *payload;
    uint32_t payload_length;
    char app_protocol[32];
    
    // Raw packet data
    const uint8_t *raw_data;
    uint32_t raw_length;
} packet_info_t;

// Parse packet into structured information
void parse_packet(const uint8_t *packet, uint32_t length, packet_info_t *info);

#endif // PARSER_H
