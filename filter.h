/* LLM code starts here */
#ifndef FILTER_H
#define FILTER_H

#include "parser.h"

// Filter types
typedef enum {
    FILTER_NONE,
    FILTER_HTTP,
    FILTER_HTTPS,
    FILTER_DNS,
    FILTER_ARP,
    FILTER_TCP,
    FILTER_UDP
} filter_type_t;

// Get filter from user
filter_type_t get_filter_choice();

// Check if packet matches filter
int packet_matches_filter(const packet_info_t *info, filter_type_t filter);

// Get BPF filter string for libpcap
const char* get_bpf_filter_string(filter_type_t filter);

#endif // FILTER_H
/* LLM code ends here */
