#ifndef DISPLAY_H
#define DISPLAY_H

#include "parser.h"
#include "cshark.h"

// Display functions
void display_banner();
void display_main_menu(const char *interface_name);
void display_packet_summary(uint32_t packet_id, struct timeval timestamp, 
                           uint32_t length, const packet_info_t *info);
void display_packet_detailed(const stored_packet_t *pkt);
void display_hex_dump(const uint8_t *data, uint32_t length, uint32_t max_bytes);
void display_full_hex_dump(const uint8_t *data, uint32_t length);
void display_session_summary(const packet_session_t *session);

#endif // DISPLAY_H
