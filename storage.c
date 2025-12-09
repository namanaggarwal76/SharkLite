#include "storage.h"
#include <stdlib.h>
#include <string.h>

// current_session is defined in main.c
extern packet_session_t current_session;

void init_session() {
    // Free previous session memory
    free_session();
    
    // Reset session
    memset(&current_session, 0, sizeof(packet_session_t));
    current_session.active = 1;
}

void store_packet(uint32_t id, struct timeval timestamp, 
                 const uint8_t *data, uint32_t length, uint32_t caplen) {
    if (current_session.count >= MAX_PACKETS) {
        return; // Session full
    }
    
    stored_packet_t *pkt = &current_session.packets[current_session.count];
    pkt->id = id;
    pkt->timestamp = timestamp;
    pkt->length = length;
    pkt->caplen = caplen;
    
    // Allocate and copy packet data
    pkt->data = (uint8_t *)malloc(caplen);
    if (pkt->data) {
        memcpy(pkt->data, data, caplen);
        current_session.count++;
    }
}

void free_session() {
    for (int i = 0; i < current_session.count; i++) {
        if (current_session.packets[i].data) {
            free(current_session.packets[i].data);
            current_session.packets[i].data = NULL;
        }
    }
    current_session.count = 0;
    current_session.active = 0;
}
