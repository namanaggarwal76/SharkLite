#ifndef CSHARK_H
#define CSHARK_H

#include <pcap.h>
#include <stdint.h>
#include <time.h>

// Maximum number of packets to store
#define MAX_PACKETS 10000
#define SNAP_LEN 65535

// Packet storage structure
