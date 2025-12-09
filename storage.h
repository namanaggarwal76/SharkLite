#ifndef STORAGE_H
#define STORAGE_H

#include "cshark.h"

// Initialize a new session (frees previous session memory)
void init_session();

// Store a packet in the current session
void store_packet(uint32_t id, struct timeval timestamp, 
                 const uint8_t *data, uint32_t length, uint32_t caplen);

// Free session memory
void free_session();

#endif // STORAGE_H
