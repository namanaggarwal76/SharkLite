#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include "filter.h"

// Start packet capture
void start_capture(const char *device, filter_type_t filter);

// Packet handler callback
void packet_handler(u_char *args, const struct pcap_pkthdr *header, 
                   const u_char *packet);

#endif // CAPTURE_H
