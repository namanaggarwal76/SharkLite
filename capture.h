#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

// Start packet capture
void start_capture(const char *device, int dummy);

// Packet handler callback
void packet_handler(u_char *args, const struct pcap_pkthdr *header, 
                   const u_char *packet);

#endif // CAPTURE_H
