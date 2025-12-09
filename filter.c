/* LLM code starts here */
#include "filter.h"
#include "colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

filter_type_t get_filter_choice() {
    int choice;
    
    printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Select a filter:\n\n");
    printf(COLOR_BOLD "1." COLOR_RESET " " COLOR_PROTOCOL "HTTP" COLOR_RESET "\n");
    printf(COLOR_BOLD "2." COLOR_RESET " " COLOR_PROTOCOL "HTTPS" COLOR_RESET "\n");
    printf(COLOR_BOLD "3." COLOR_RESET " " COLOR_PROTOCOL "DNS" COLOR_RESET "\n");
    printf(COLOR_BOLD "4." COLOR_RESET " " COLOR_PROTOCOL "ARP" COLOR_RESET "\n");
    printf(COLOR_BOLD "5." COLOR_RESET " " COLOR_PROTOCOL "TCP" COLOR_RESET "\n");
    printf(COLOR_BOLD "6." COLOR_RESET " " COLOR_PROTOCOL "UDP" COLOR_RESET "\n");
    printf("\n" COLOR_LABEL "Enter your choice (1-6): " COLOR_RESET);
    
    if (scanf("%d", &choice) != 1) {
        // Check for EOF (Ctrl+D) - terminate program
        if (feof(stdin)) {
            printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Cleaning up and exiting...\n");
            printf(COLOR_SUCCESS "[C-Shark] Goodbye!" COLOR_RESET "\n\n");
            exit(0);
        }
        return FILTER_NONE;
    }
    
    switch (choice) {
        case 1: return FILTER_HTTP;
        case 2: return FILTER_HTTPS;
        case 3: return FILTER_DNS;
        case 4: return FILTER_ARP;
        case 5: return FILTER_TCP;
        case 6: return FILTER_UDP;
        default: return FILTER_NONE;
    }
}

int packet_matches_filter(const packet_info_t *info, filter_type_t filter) {
    switch (filter) {
        case FILTER_NONE:
            return 1;
        
        case FILTER_HTTP:
            return (info->src_port == 80 || info->dst_port == 80);
        
        case FILTER_HTTPS:
            return (info->src_port == 443 || info->dst_port == 443);
        
        case FILTER_DNS:
            return (info->src_port == 53 || info->dst_port == 53);
        
        case FILTER_ARP:
            return (info->ethertype == 0x0806);
        
        case FILTER_TCP:
            return (info->protocol == 6);
        
        case FILTER_UDP:
            return (info->protocol == 17);
        
        default:
            return 0;
    }
}

const char* get_bpf_filter_string(filter_type_t filter) {
    switch (filter) {
        case FILTER_HTTP:
            return "tcp port 80";
        case FILTER_HTTPS:
            return "tcp port 443";
        case FILTER_DNS:
            return "port 53";
        case FILTER_ARP:
            return "arp";
        case FILTER_TCP:
            return "tcp";
        case FILTER_UDP:
            return "udp";
        default:
            return "";
    }
}
/* LLM code ends here */
