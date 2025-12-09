/* LLM code starts here */
#include "interface.h"
#include "colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void discover_interfaces(char *selected_device, int *device_index) {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    int choice;
    
    printf("\n" COLOR_BOLD COLOR_CYAN "[C-Shark] The Terminal Packet Predator" COLOR_RESET "\n");
    printf(COLOR_SEPARATOR "==============================================" COLOR_RESET "\n");
    printf(COLOR_HEADER "[C-Shark]" COLOR_RESET " Searching for available interfaces...\n");
    
    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, COLOR_ERROR "Error finding devices: %s" COLOR_RESET "\n", errbuf);
        exit(1);
    }
    
    if (alldevs == NULL) {
        fprintf(stderr, COLOR_ERROR "No interfaces found!" COLOR_RESET "\n");
        exit(1);
    }
    
    printf(COLOR_SUCCESS "Found!" COLOR_RESET "\n\n");
    
    // Display all interfaces
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        i++;
        printf(COLOR_BOLD "%d." COLOR_RESET " " COLOR_YELLOW "%s" COLOR_RESET, i, dev->name);
        if (dev->description) {
            printf(COLOR_DIM " (%s)" COLOR_RESET, dev->description);
        }
        printf("\n");
    }
    
    printf("\n" COLOR_LABEL "Select an interface to sniff (1-%d): " COLOR_RESET, i);
    
    if (scanf("%d", &choice) != 1) {
        if (feof(stdin)) {
            printf("\nExiting C-Shark...\n");
            pcap_freealldevs(alldevs);
            exit(0);
        }
        fprintf(stderr, "\nInvalid choice!\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    
    if (choice < 1 || choice > i) {
        fprintf(stderr, COLOR_ERROR "Invalid choice!" COLOR_RESET "\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    
    // Get the selected device
    dev = alldevs;
    for (int j = 1; j < choice; j++) {
        dev = dev->next;
    }
    
    strcpy(selected_device, dev->name);
    *device_index = choice;
    
    pcap_freealldevs(alldevs);
}
/* LLM code ends here */
