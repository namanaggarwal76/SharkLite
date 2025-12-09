#include "display.h"
#include "colors.h"
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

// Helper function to get port name
static const char* get_port_name(uint16_t port) {
    switch (port) {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "TELNET";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 3306: return "MySQL";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-ALT";
        default: return NULL;
    }
}

void display_banner() {
    printf("\n");
    printf(COLOR_BOLD COLOR_CYAN);
    printf(" ██████╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗\n");
    printf("██╔════╝██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝\n");
    printf("██║     ███████╗███████║███████║██████╔╝█████╔╝ \n");
    printf("██║     ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ \n");
    printf("╚██████╗███████║██║  ██║██║  ██║██║  ██║██║  ██╗\n");
    printf(" ╚═════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝\n");
    printf(COLOR_RESET);
    printf("\n");
}

void display_main_menu(const char *interface_name) {
    printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Interface " COLOR_BOLD COLOR_YELLOW "'%s'" COLOR_RESET " selected. What's next?\n\n", interface_name);
    printf(COLOR_BOLD "1." COLOR_RESET " Start Sniffing (All Packets)\n");
    printf(COLOR_BOLD "2." COLOR_RESET " Start Sniffing (With Filters)\n");
    printf(COLOR_BOLD "3." COLOR_RESET " Inspect Last Session\n");
    printf(COLOR_BOLD "4." COLOR_RESET " Exit C-Shark\n");
    printf("\n" COLOR_LABEL "Enter your choice (1-4): " COLOR_RESET);
}

void display_packet_summary(uint32_t packet_id, struct timeval timestamp, 
                           uint32_t length, const packet_info_t *info) {
    printf("\n" COLOR_SEPARATOR "-----------------------------------------" COLOR_RESET "\n");
    printf(COLOR_LABEL "Packet " COLOR_PACKET_ID "#%u" COLOR_RESET " | " 
           COLOR_TIMESTAMP "Timestamp: %ld.%06ld" COLOR_RESET " | " 
           COLOR_LABEL "Length: " COLOR_VALUE "%u bytes" COLOR_RESET "\n",
           packet_id, (long)timestamp.tv_sec, (long)timestamp.tv_usec, length);
    
    // Layer 2 (Ethernet)
    printf(COLOR_HEADER "L2 (Ethernet):" COLOR_RESET " Dst MAC: " COLOR_MAC "%02X:%02X:%02X:%02X:%02X:%02X" COLOR_RESET 
           " | Src MAC: " COLOR_MAC "%02X:%02X:%02X:%02X:%02X:%02X" COLOR_RESET " |\n",
           info->dst_mac[0], info->dst_mac[1], info->dst_mac[2],
           info->dst_mac[3], info->dst_mac[4], info->dst_mac[5],
           info->src_mac[0], info->src_mac[1], info->src_mac[2],
           info->src_mac[3], info->src_mac[4], info->src_mac[5]);
    
    printf("               " COLOR_LABEL "EtherType: " COLOR_PROTOCOL);
    if (info->ethertype == ETHERTYPE_IP) {
        printf("IPv4 (0x%04X)", info->ethertype);
    } else if (info->ethertype == ETHERTYPE_IPV6) {
        printf("IPv6 (0x%04X)", info->ethertype);
    } else if (info->ethertype == ETHERTYPE_ARP) {
        printf("ARP (0x%04X)", info->ethertype);
    } else {
        printf("Unknown (0x%04X)", info->ethertype);
    }
    printf(COLOR_RESET "\n");
    
    // Layer 3 (Network)
    if (info->ip_version == 4) {
        printf(COLOR_HEADER "L3 (IPv4):" COLOR_RESET " Src IP: " COLOR_IP "%s" COLOR_RESET 
               " | Dst IP: " COLOR_IP "%s" COLOR_RESET " | " COLOR_LABEL "Protocol: " COLOR_PROTOCOL, 
               info->src_ip, info->dst_ip);
        
        if (info->protocol == 6) printf("TCP (6)");
        else if (info->protocol == 17) printf("UDP (17)");
        else if (info->protocol == 1) printf("ICMP (1)");
        else printf("Unknown (%d)", info->protocol);
        
        printf(COLOR_RESET " | " COLOR_LABEL "TTL: " COLOR_VALUE "%u" COLOR_RESET "\n", info->ttl);
        printf("           " COLOR_LABEL "ID: " COLOR_VALUE "0x%04X" COLOR_RESET 
               " | " COLOR_LABEL "Total Length: " COLOR_VALUE "%u" COLOR_RESET 
               " | " COLOR_LABEL "Header Length: " COLOR_VALUE "%u bytes" COLOR_RESET,
               info->ip_id, info->total_length, info->ip_header_length);
        
        if (info->flags) {
            printf(" | " COLOR_LABEL "Flags:" COLOR_FLAGS);
            if (info->flags & 0x8000) printf(" [Reserved]");
            if (info->flags & 0x4000) printf(" [DF]");
            if (info->flags & 0x2000) printf(" [MF]");
            printf(COLOR_RESET);
        }
        printf("\n");
        
    } else if (info->ip_version == 6) {
        printf(COLOR_HEADER "L3 (IPv6):" COLOR_RESET " Src IP: " COLOR_IP "%s" COLOR_RESET 
               " | Dst IP: " COLOR_IP "%s" COLOR_RESET "\n",
               info->src_ip, info->dst_ip);
        printf("           " COLOR_LABEL "Next Header: " COLOR_PROTOCOL);
        
        if (info->protocol == 6) printf("TCP (6)");
        else if (info->protocol == 17) printf("UDP (17)");
        else if (info->protocol == 58) printf("ICMPv6 (58)");
        else printf("Unknown (%d)", info->protocol);
        
        printf(COLOR_RESET " | " COLOR_LABEL "Hop Limit: " COLOR_VALUE "%u" COLOR_RESET 
               " | " COLOR_LABEL "Traffic Class: " COLOR_VALUE "%u" COLOR_RESET 
               " | " COLOR_LABEL "Flow Label: " COLOR_VALUE "0x%05X" COLOR_RESET 
               " | " COLOR_LABEL "Payload Length: " COLOR_VALUE "%u" COLOR_RESET "\n",
               info->hop_limit, info->traffic_class, info->flow_label, info->ipv6_payload_length);
        
    } else if (info->ethertype == ETHERTYPE_ARP) {
        printf("\n" COLOR_HEADER "L3 (ARP):" COLOR_RESET " " COLOR_LABEL "Operation: " COLOR_PROTOCOL);
        
        if (info->arp_opcode == 1) printf("Request (1)");
        else if (info->arp_opcode == 2) printf("Reply (2)");
        else printf("Unknown (%u)", info->arp_opcode);
        
        printf(COLOR_RESET " | " COLOR_LABEL "Sender IP: " COLOR_IP "%s" COLOR_RESET 
               " | " COLOR_LABEL "Target IP: " COLOR_IP "%s" COLOR_RESET "\n", info->arp_spa, info->arp_tpa);
        printf("          " COLOR_LABEL "Sender MAC: " COLOR_MAC "%02X:%02X:%02X:%02X:%02X:%02X" COLOR_RESET 
               " | " COLOR_LABEL "Target MAC: " COLOR_MAC "%02X:%02X:%02X:%02X:%02X:%02X" COLOR_RESET "\n",
               info->arp_sha[0], info->arp_sha[1], info->arp_sha[2],
               info->arp_sha[3], info->arp_sha[4], info->arp_sha[5],
               info->arp_tha[0], info->arp_tha[1], info->arp_tha[2],
               info->arp_tha[3], info->arp_tha[4], info->arp_tha[5]);
        printf("          " COLOR_LABEL "HW Type: " COLOR_VALUE "%u" COLOR_RESET 
               " | " COLOR_LABEL "Proto Type: " COLOR_VALUE "0x%04X" COLOR_RESET 
               " | " COLOR_LABEL "HW Len: " COLOR_VALUE "%u" COLOR_RESET 
               " | " COLOR_LABEL "Proto Len: " COLOR_VALUE "%u" COLOR_RESET "\n",
               info->arp_htype, info->arp_ptype, info->arp_hlen, info->arp_plen);
    }
    
    // Layer 4 (Transport)
    if (info->protocol == 6 && info->src_port > 0) { // TCP
        const char *src_name = get_port_name(info->src_port);
        const char *dst_name = get_port_name(info->dst_port);
        
        printf(COLOR_HEADER "L4 (TCP):" COLOR_RESET " " COLOR_LABEL "Src Port: " COLOR_PORT "%u" COLOR_RESET, info->src_port);
        if (src_name) printf(COLOR_PROTOCOL " (%s)" COLOR_RESET, src_name);
        printf(" | " COLOR_LABEL "Dst Port: " COLOR_PORT "%u" COLOR_RESET, info->dst_port);
        if (dst_name) printf(COLOR_PROTOCOL " (%s)" COLOR_RESET, dst_name);
        printf(" | " COLOR_LABEL "Seq: " COLOR_VALUE "%u" COLOR_RESET 
               " | " COLOR_LABEL "Ack: " COLOR_VALUE "%u" COLOR_RESET "\n", info->seq_num, info->ack_num);
        
        printf("          | " COLOR_LABEL "Flags: " COLOR_FLAGS "[");
        int first = 1;
        if (info->tcp_flags & 0x02) { if (!first) printf(","); printf("SYN"); first = 0; }
        if (info->tcp_flags & 0x10) { if (!first) printf(","); printf("ACK"); first = 0; }
        if (info->tcp_flags & 0x01) { if (!first) printf(","); printf("FIN"); first = 0; }
        if (info->tcp_flags & 0x04) { if (!first) printf(","); printf("RST"); first = 0; }
        if (info->tcp_flags & 0x08) { if (!first) printf(","); printf("PSH"); first = 0; }
        if (info->tcp_flags & 0x20) { if (!first) printf(","); printf("URG"); first = 0; }
        printf("]" COLOR_RESET "\n");
        
        printf("          " COLOR_LABEL "Window: " COLOR_VALUE "%u" COLOR_RESET 
               " | " COLOR_LABEL "Checksum: " COLOR_VALUE "0x%04X" COLOR_RESET 
               " | " COLOR_LABEL "Header Length: " COLOR_VALUE "%u bytes" COLOR_RESET "\n",
               info->window_size, info->tcp_checksum, info->tcp_header_length);
        
    } else if (info->protocol == 17 && info->src_port > 0) { // UDP
        const char *src_name = get_port_name(info->src_port);
        const char *dst_name = get_port_name(info->dst_port);
        
        printf(COLOR_HEADER "L4 (UDP):" COLOR_RESET " " COLOR_LABEL "Src Port: " COLOR_PORT "%u" COLOR_RESET, info->src_port);
        if (src_name) printf(COLOR_PROTOCOL " (%s)" COLOR_RESET, src_name);
        printf(" | " COLOR_LABEL "Dst Port: " COLOR_PORT "%u" COLOR_RESET, info->dst_port);
        if (dst_name) printf(COLOR_PROTOCOL " (%s)" COLOR_RESET, dst_name);
        printf(" | " COLOR_LABEL "Length: " COLOR_VALUE "%u" COLOR_RESET 
               " | " COLOR_LABEL "Checksum: " COLOR_VALUE "0x%04X" COLOR_RESET "\n",
               info->udp_length, info->udp_checksum);
    }
    
    // Layer 7 (Payload)
    if (info->payload_length > 0) {
        printf(COLOR_HEADER "L7 (Payload):" COLOR_RESET " Identified as " COLOR_PROTOCOL "%s" COLOR_RESET " on port ", info->app_protocol);
        
        if (info->protocol == 6) {
            printf(COLOR_PORT "%u" COLOR_RESET " - " COLOR_VALUE "%u bytes" COLOR_RESET "\n", 
                   (info->src_port == 80 || info->src_port == 443 || info->src_port == 53) 
                   ? info->src_port : info->dst_port,
                   info->payload_length);
        } else if (info->protocol == 17) {
            printf(COLOR_PORT "%u" COLOR_RESET " - " COLOR_VALUE "%u bytes" COLOR_RESET "\n",
                   (info->src_port == 53) ? info->src_port : info->dst_port,
                   info->payload_length);
        }
        
        printf(COLOR_LABEL "Data (first 64 bytes):" COLOR_RESET "\n");
        display_hex_dump(info->payload, info->payload_length, 64);
    }
}

void display_hex_dump(const uint8_t *data, uint32_t length, uint32_t max_bytes) {
    uint32_t bytes_to_show = (length < max_bytes) ? length : max_bytes;
    
    for (uint32_t i = 0; i < bytes_to_show; i += 16) {
        // Print hex
        printf(COLOR_HEX);
        for (uint32_t j = 0; j < 16 && (i + j) < bytes_to_show; j++) {
            printf("%02X ", data[i + j]);
        }
        printf(COLOR_RESET);
        
        // Pad if less than 16 bytes
        for (uint32_t j = bytes_to_show - i; j < 16; j++) {
            printf("   ");
        }
        
        // Print ASCII
        printf(COLOR_ASCII);
        for (uint32_t j = 0; j < 16 && (i + j) < bytes_to_show; j++) {
            uint8_t c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf(COLOR_RESET "\n");
    }
}

void display_full_hex_dump(const uint8_t *data, uint32_t length) {
    for (uint32_t i = 0; i < length; i += 16) {
        printf(COLOR_DIM "%04X:" COLOR_RESET " ", i);
        
        // Print hex
        printf(COLOR_HEX);
        for (uint32_t j = 0; j < 16 && (i + j) < length; j++) {
            printf("%02X ", data[i + j]);
        }
        printf(COLOR_RESET);
        
        // Pad if less than 16 bytes
        for (uint32_t j = length - i; j < 16; j++) {
            printf("   ");
        }
        
        printf(COLOR_SEPARATOR " | " COLOR_RESET);
        
        // Print ASCII
        printf(COLOR_ASCII);
        for (uint32_t j = 0; j < 16 && (i + j) < length; j++) {
            uint8_t c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf(COLOR_RESET "\n");
    }
}

void display_packet_detailed(const stored_packet_t *pkt) {
    packet_info_t info;
    parse_packet(pkt->data, pkt->caplen, &info);
    
    printf("\n");
    printf(COLOR_BOLD COLOR_CYAN "=========================================\n");
    printf("       DETAILED PACKET INSPECTION\n");
    printf("=========================================" COLOR_RESET "\n");
    printf(COLOR_LABEL "Packet ID: " COLOR_PACKET_ID "%u" COLOR_RESET "\n", pkt->id);
    printf(COLOR_LABEL "Timestamp: " COLOR_TIMESTAMP "%ld.%06ld" COLOR_RESET "\n", (long)pkt->timestamp.tv_sec, (long)pkt->timestamp.tv_usec);
    printf(COLOR_LABEL "Captured Length: " COLOR_VALUE "%u bytes" COLOR_RESET "\n", pkt->caplen);
    printf(COLOR_LABEL "Actual Length: " COLOR_VALUE "%u bytes" COLOR_RESET "\n", pkt->length);
    printf(COLOR_SEPARATOR "-----------------------------------------" COLOR_RESET "\n\n");
    
    // Display parsed information
    display_packet_summary(pkt->id, pkt->timestamp, pkt->length, &info);
    
    // Display full hex dump
    printf("\n" COLOR_SEPARATOR "-----------------------------------------" COLOR_RESET "\n");
    printf(COLOR_BOLD COLOR_YELLOW "FULL PACKET HEX DUMP:" COLOR_RESET "\n");
    printf(COLOR_SEPARATOR "-----------------------------------------" COLOR_RESET "\n");
    display_full_hex_dump(pkt->data, pkt->caplen);
    printf("\n");
}

void display_session_summary(const packet_session_t *session) {
    if (!session->active || session->count == 0) {
        printf("\n" COLOR_ERROR "[C-Shark] No session data available. Please capture packets first." COLOR_RESET "\n");
        return;
    }
    
    printf("\n" COLOR_HEADER "[C-Shark] Last Session Summary" COLOR_RESET " - " COLOR_SUCCESS "%d packets captured" COLOR_RESET "\n", session->count);
    printf(COLOR_SEPARATOR "==============================================" COLOR_RESET "\n");
    
    for (int i = 0; i < session->count; i++) {
        stored_packet_t *pkt = (stored_packet_t *)&session->packets[i];
        packet_info_t info;
        parse_packet(pkt->data, pkt->caplen, &info);
        
        printf(COLOR_PACKET_ID "%4d" COLOR_RESET " | " 
               COLOR_TIMESTAMP "%ld.%06ld" COLOR_RESET " | " 
               COLOR_VALUE "%5u bytes" COLOR_RESET " | ", 
               pkt->id,
               (long)pkt->timestamp.tv_sec,
               (long)pkt->timestamp.tv_usec,
               pkt->length);
        
        // Basic L3/L4 info
        if (info.ip_version == 4) {
            printf(COLOR_PROTOCOL "IPv4" COLOR_RESET " " COLOR_IP "%s" COLOR_RESET " -> " COLOR_IP "%s" COLOR_RESET, info.src_ip, info.dst_ip);
        } else if (info.ip_version == 6) {
            printf(COLOR_PROTOCOL "IPv6" COLOR_RESET " " COLOR_IP "%s" COLOR_RESET " -> " COLOR_IP "%s" COLOR_RESET, info.src_ip, info.dst_ip);
        } else if (info.ethertype == ETHERTYPE_ARP) {
            printf(COLOR_PROTOCOL "ARP" COLOR_RESET);
        } else {
            printf(COLOR_DIM "Unknown" COLOR_RESET);
        }
        
        if (info.protocol == 6) {
            printf(" | " COLOR_PROTOCOL "TCP:" COLOR_PORT "%u" COLOR_RESET "->" COLOR_PORT "%u" COLOR_RESET, info.src_port, info.dst_port);
        } else if (info.protocol == 17) {
            printf(" | " COLOR_PROTOCOL "UDP:" COLOR_PORT "%u" COLOR_RESET "->" COLOR_PORT "%u" COLOR_RESET, info.src_port, info.dst_port);
        }
        
        printf("\n");
    }
    
    printf("\n" COLOR_LABEL "Enter packet ID to inspect (or 0 to return): " COLOR_RESET);
}
