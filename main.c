#include <stdio.h>
#include <stdlib.h>
#include "colors.h"
#include "interface.h"

int main() {
    char selected_device[256];
    int device_index;
    discover_interfaces(selected_device, &device_index);
    printf("Selected: %s\n", selected_device);
    return 0;
}
