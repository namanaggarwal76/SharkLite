#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include "cshark.h"
#include "interface.h"
#include "capture.h"
#include "display.h"
#include "filter.h"
#include "storage.h"
#include "colors.h"

packet_session_t current_session = {0};
volatile int stop_capture = 0;

pcap_t *global_handle = NULL;

void handle_sigint(int sig) {
    (void)sig; // Suppress unused parameter warning
    stop_capture = 1;
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
}

void handle_sigquit(int sig) {
    (void)sig; // Suppress unused parameter warning
    printf("\n\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Cleaning up and exiting...\n");
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
    free_session();
    printf(COLOR_SUCCESS "[C-Shark] Goodbye!" COLOR_RESET "\n\n");
    exit(0);
}

void inspect_last_session() {
    if (!current_session.active || current_session.count == 0) {
        printf("\n" COLOR_ERROR "[C-Shark] No session data available. Please capture packets first." COLOR_RESET "\n");
        return;
    }
    
    while (1) {
        // Check if Ctrl+C was pressed to return to main menu
        if (stop_capture) {
            printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Returning to main menu...\n");
            stop_capture = 0;
            return;
        }
        
        display_session_summary(&current_session);
        
        int packet_id;
        if (scanf("%d", &packet_id) != 1) {
            // Check for EOF (Ctrl+D) - terminate program
            if (feof(stdin)) {
                printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Cleaning up and exiting...\n");
                free_session();
                printf(COLOR_SUCCESS "[C-Shark] Goodbye!" COLOR_RESET "\n\n");
                exit(0);
            }
            // Clear input buffer for invalid input
            while (getchar() != '\n');
            printf(COLOR_ERROR "[C-Shark] Invalid input." COLOR_RESET "\n");
            continue;
        }
        
        if (packet_id == 0) {
            break;
        }
        
        // Find packet by ID
        int found = 0;
        for (int i = 0; i < current_session.count; i++) {
            if (current_session.packets[i].id == (uint32_t)packet_id) {
                display_packet_detailed(&current_session.packets[i]);
                found = 1;
                break;
            }
        }
        
        if (!found) {
            printf("\n" COLOR_ERROR "[C-Shark] Packet ID %d not found." COLOR_RESET "\n", packet_id);
        }
        
        printf("\nPress Enter to continue...");
        while (getchar() != '\n');
        getchar();
        
        // Check if Ctrl+C was pressed after viewing packet
        if (stop_capture) {
            printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Returning to main menu...\n");
            stop_capture = 0;
            return;
        }
    }
}

int main(int argc, char *argv[]) {
    (void)argc; // Suppress unused parameter warning
    (void)argv; // Suppress unused parameter warning
    char selected_device[256];
    int device_index;
    int choice;
    
    // Set up signal handlers
    signal(SIGINT, handle_sigint);   // Ctrl+C - return to menu
    signal(SIGQUIT, handle_sigquit); // Ctrl+\ - exit program
    
    // Display banner
    display_banner();
    
    // Discover and select interface
    discover_interfaces(selected_device, &device_index);
    
    // Main loop
    while (1) {
        display_main_menu(selected_device);
        
        if (scanf("%d", &choice) != 1) {
            // Check for EOF (Ctrl+D)
            if (feof(stdin)) {
                printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Cleaning up and exiting...\n");
                free_session();
                printf(COLOR_SUCCESS "[C-Shark] Goodbye!" COLOR_RESET "\n\n");
                return 0;
            }
            // Clear input buffer for invalid input
            while (getchar() != '\n');
            printf("\n" COLOR_ERROR "[C-Shark] Invalid input. Please try again." COLOR_RESET "\n");
            continue;
        }
        
        // Clear input buffer
        while (getchar() != '\n');
        
        switch (choice) {
            case 1: // Start Sniffing (All Packets)
                start_capture(selected_device, FILTER_NONE);
                stop_capture = 0;
                break;
                
            case 2: { // Start Sniffing (With Filters)
                filter_type_t filter = get_filter_choice();
                if (filter == FILTER_NONE) {
                    printf("\n" COLOR_ERROR "[C-Shark] Invalid filter choice." COLOR_RESET "\n");
                    break;
                }
                start_capture(selected_device, filter);
                stop_capture = 0;
                break;
            }
            
            case 3: // Inspect Last Session
                inspect_last_session();
                break;
                
            case 4: // Exit
                printf("\n" COLOR_HEADER "[C-Shark]" COLOR_RESET " Cleaning up and exiting...\n");
                free_session();
                printf(COLOR_SUCCESS "[C-Shark] Goodbye!" COLOR_RESET "\n\n");
                return 0;
                
            default:
                printf("\n" COLOR_ERROR "[C-Shark] Invalid choice. Please select 1-4." COLOR_RESET "\n");
        }
    }
    
    return 0;
}
