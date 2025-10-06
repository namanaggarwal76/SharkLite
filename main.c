#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "colors.h"
#include "interface.h"
#include "capture.h"

volatile int stop_capture = 0;
pcap_t *global_handle = NULL;

void handle_sigint(int sig) {
    stop_capture = 1;
    if (global_handle) pcap_breakloop(global_handle);
}

int main() {
    char selected_device[256];
    int device_index;
    signal(SIGINT, handle_sigint);
    discover_interfaces(selected_device, &device_index);
    start_capture(selected_device, 0);
    return 0;
}
