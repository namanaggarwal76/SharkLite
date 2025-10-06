#ifndef CSHARK_H
#define CSHARK_H

#include <pcap.h>
#include <stdint.h>
#include <time.h>

// Maximum number of packets to store
#define MAX_PACKETS 10000
#define SNAP_LEN 65535

// Packet storage structure
typedef struct {
    uint32_t id;
    struct timeval timestamp;
    uint32_t length;
    uint8_t *data;
    uint32_t caplen;
} stored_packet_t;

// Session storage
typedef struct {
    stored_packet_t packets[MAX_PACKETS];
    int count;
    int active;
} packet_session_t;

// Global session
extern packet_session_t current_session;
extern volatile int stop_capture;

#endif // CSHARK_H
