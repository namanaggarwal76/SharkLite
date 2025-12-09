/* LLM code starts here */
#include "capture.h"
#include "parser.h"
#include "display.h"
#include "storage.h"
#include "colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

// stop_capture is defined in main.c
extern volatile int stop_capture;
static uint32_t packet_counter = 0;
static filter_type_t current_filter = FILTER_NONE;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, 
                   const u_char *packet) {
    (void)args; // Suppress unused parameter warning
    packet_counter++;
    
    // Parse packet
    packet_info_t info;
    parse_packet(packet, header->caplen, &info);
    
    // Check if packet matches filter
    if (!packet_matches_filter(&info, current_filter)) {
        return;
    }
    
    // Store packet in session
    store_packet(packet_counter, header->ts, packet, header->len, header->caplen);
    
    // Display packet summary
    display_packet_summary(packet_counter, header->ts, header->len, &info);
}

// External global handle for signal handling
extern pcap_t *global_handle;

void start_capture(const char *device, filter_type_t filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    
    current_filter = filter;
    packet_counter = 0;
    stop_capture = 0;
    
    // Initialize new session
    init_session();
    
    // Get network number and mask
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, COLOR_WARNING "Warning: Couldn't get netmask for device %s: %s" COLOR_RESET "\n", device, errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open device for sniffing
    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, COLOR_ERROR "Error opening device %s: %s" COLOR_RESET "\n", device, errbuf);
        return;
    }
    
    // Set global handle for signal handler
    global_handle = handle;
    
    // Apply BPF filter if specified
    const char *filter_str = get_bpf_filter_string(filter);
    if (filter != FILTER_NONE && strlen(filter_str) > 0) {
        if (pcap_compile(handle, &fp, filter_str, 0, net) == -1) {
            fprintf(stderr, COLOR_ERROR "Error compiling filter: %s" COLOR_RESET "\n", pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, COLOR_ERROR "Error setting filter: %s" COLOR_RESET "\n", pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return;
        }
        
        pcap_freecode(&fp);
        printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Filter applied: " COLOR_SUCCESS "%s" COLOR_RESET "\n", filter_str);
    }
    
    printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Starting packet capture on " COLOR_YELLOW "%s" COLOR_RESET "...\n", device);
    printf(COLOR_HEADER "[C-Shark]" COLOR_RESET " Press " COLOR_BOLD "Ctrl+C" COLOR_RESET " to stop capture, " COLOR_BOLD "Ctrl+\\" COLOR_RESET " to exit\n");
    printf(COLOR_SEPARATOR "=========================================" COLOR_RESET "\n");
    
    // Start capturing packets
    pcap_loop(handle, -1, packet_handler, NULL);
    
    // Cleanup
    global_handle = NULL;
    pcap_close(handle);
    
    printf("\n\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Capture stopped. Captured " COLOR_SUCCESS "%u packets" COLOR_RESET ".\n", packet_counter);
}
/* LLM code ends here */
