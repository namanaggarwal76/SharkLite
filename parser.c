/* LLM code starts here */
#include "parser.h"
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>

void parse_packet(const uint8_t *packet, uint32_t length, packet_info_t *info) {
    memset(info, 0, sizeof(packet_info_t));
    info->raw_data = packet;
    info->raw_length = length;
    
    if (length < 14) return; // Too small for Ethernet header
    
    // Parse Ethernet header (Layer 2)
    struct ether_header *eth = (struct ether_header *)packet;
    memcpy(info->dst_mac, eth->ether_dhost, 6);
    memcpy(info->src_mac, eth->ether_shost, 6);
    info->ethertype = ntohs(eth->ether_type);
    
    const uint8_t *l3_packet = packet + 14;
    uint32_t l3_length = length - 14;
    
    // Parse based on EtherType
    if (info->ethertype == ETHERTYPE_IP) { // IPv4
        if (l3_length < 20) return;
        
        struct ip *iph = (struct ip *)l3_packet;
        info->ip_version = 4;
        info->protocol = iph->ip_p;
        info->ttl = iph->ip_ttl;
        info->ip_id = ntohs(iph->ip_id);
        info->total_length = ntohs(iph->ip_len);
        info->ip_header_length = iph->ip_hl * 4;
        info->flags = ntohs(iph->ip_off) & 0xE000;
        
        inet_ntop(AF_INET, &(iph->ip_src), info->src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->ip_dst), info->dst_ip, INET_ADDRSTRLEN);
        
        const uint8_t *l4_packet = l3_packet + info->ip_header_length;
        uint32_t l4_length = l3_length - info->ip_header_length;
        
        // Parse Layer 4
        if (info->protocol == IPPROTO_TCP && l4_length >= 20) {
            struct tcphdr *tcph = (struct tcphdr *)l4_packet;
            info->src_port = ntohs(tcph->th_sport);
            info->dst_port = ntohs(tcph->th_dport);
            info->seq_num = ntohl(tcph->th_seq);
            info->ack_num = ntohl(tcph->th_ack);
            info->tcp_flags = tcph->th_flags;
            info->window_size = ntohs(tcph->th_win);
            info->tcp_checksum = ntohs(tcph->th_sum);
            info->tcp_header_length = tcph->th_off * 4;
            
            // Identify application protocol
            if (info->src_port == 80 || info->dst_port == 80) {
                strcpy(info->app_protocol, "HTTP");
            } else if (info->src_port == 443 || info->dst_port == 443) {
                strcpy(info->app_protocol, "HTTPS/TLS");
            } else {
                strcpy(info->app_protocol, "Unknown");
            }
            
            // Set payload
            if (l4_length > info->tcp_header_length) {
                info->payload = l4_packet + info->tcp_header_length;
                info->payload_length = l4_length - info->tcp_header_length;
            }
            
        } else if (info->protocol == IPPROTO_UDP && l4_length >= 8) {
            struct udphdr *udph = (struct udphdr *)l4_packet;
            info->src_port = ntohs(udph->uh_sport);
            info->dst_port = ntohs(udph->uh_dport);
            info->udp_length = ntohs(udph->uh_ulen);
            info->udp_checksum = ntohs(udph->uh_sum);
            
            // Identify application protocol
            if (info->src_port == 53 || info->dst_port == 53) {
                strcpy(info->app_protocol, "DNS");
            } else {
                strcpy(info->app_protocol, "Unknown");
            }
            
            // Set payload
            if (l4_length > 8) {
                info->payload = l4_packet + 8;
                info->payload_length = l4_length - 8;
            }
        }
        
    } else if (info->ethertype == ETHERTYPE_IPV6) { // IPv6
        if (l3_length < 40) return;
        
        struct ip6_hdr *ip6h = (struct ip6_hdr *)l3_packet;
        info->ip_version = 6;
        info->protocol = ip6h->ip6_nxt;
        info->hop_limit = ip6h->ip6_hlim;
        info->traffic_class = (ntohl(ip6h->ip6_flow) >> 20) & 0xFF;
        info->flow_label = ntohl(ip6h->ip6_flow) & 0xFFFFF;
        info->ipv6_payload_length = ntohs(ip6h->ip6_plen);
        
        inet_ntop(AF_INET6, &(ip6h->ip6_src), info->src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6h->ip6_dst), info->dst_ip, INET6_ADDRSTRLEN);
        
        const uint8_t *l4_packet = l3_packet + 40;
        uint32_t l4_length = l3_length - 40;
        
        // Parse Layer 4
        if (info->protocol == IPPROTO_TCP && l4_length >= 20) {
            struct tcphdr *tcph = (struct tcphdr *)l4_packet;
            info->src_port = ntohs(tcph->th_sport);
            info->dst_port = ntohs(tcph->th_dport);
            info->seq_num = ntohl(tcph->th_seq);
            info->ack_num = ntohl(tcph->th_ack);
            info->tcp_flags = tcph->th_flags;
            info->window_size = ntohs(tcph->th_win);
            info->tcp_checksum = ntohs(tcph->th_sum);
            info->tcp_header_length = tcph->th_off * 4;
            
            // Identify application protocol
            if (info->src_port == 80 || info->dst_port == 80) {
                strcpy(info->app_protocol, "HTTP");
            } else if (info->src_port == 443 || info->dst_port == 443) {
                strcpy(info->app_protocol, "HTTPS/TLS");
            } else {
                strcpy(info->app_protocol, "Unknown");
            }
            
            // Set payload
            if (l4_length > info->tcp_header_length) {
                info->payload = l4_packet + info->tcp_header_length;
                info->payload_length = l4_length - info->tcp_header_length;
            }
            
        } else if (info->protocol == IPPROTO_UDP && l4_length >= 8) {
            struct udphdr *udph = (struct udphdr *)l4_packet;
            info->src_port = ntohs(udph->uh_sport);
            info->dst_port = ntohs(udph->uh_dport);
            info->udp_length = ntohs(udph->uh_ulen);
            info->udp_checksum = ntohs(udph->uh_sum);
            
            // Identify application protocol
            if (info->src_port == 53 || info->dst_port == 53) {
                strcpy(info->app_protocol, "DNS");
            } else {
                strcpy(info->app_protocol, "Unknown");
            }
            
            // Set payload
            if (l4_length > 8) {
                info->payload = l4_packet + 8;
                info->payload_length = l4_length - 8;
            }
        }
        
    } else if (info->ethertype == ETHERTYPE_ARP) { // ARP
        if (l3_length < sizeof(struct arphdr) + 20) return;
        
        struct arphdr *arph = (struct arphdr *)l3_packet;
        info->arp_opcode = ntohs(arph->ar_op);
        info->arp_htype = ntohs(arph->ar_hrd);
        info->arp_ptype = ntohs(arph->ar_pro);
        info->arp_hlen = arph->ar_hln;
        info->arp_plen = arph->ar_pln;
        
        // ARP data follows the header
        const uint8_t *arp_data = l3_packet + sizeof(struct arphdr);
        memcpy(info->arp_sha, arp_data, 6);
        arp_data += 6;
        
        struct in_addr spa;
        memcpy(&spa, arp_data, 4);
        inet_ntop(AF_INET, &spa, info->arp_spa, INET_ADDRSTRLEN);
        arp_data += 4;
        
        memcpy(info->arp_tha, arp_data, 6);
        arp_data += 6;
        
        struct in_addr tpa;
        memcpy(&tpa, arp_data, 4);
        inet_ntop(AF_INET, &tpa, info->arp_tpa, INET_ADDRSTRLEN);
    }
}
/* LLM code ends here */
