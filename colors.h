#ifndef COLORS_H
#define COLORS_H

// ANSI Color codes
#define COLOR_RESET         "\033[0m"
#define COLOR_BOLD          "\033[1m"
#define COLOR_DIM           "\033[2m"

// Foreground colors
#define COLOR_BLACK         "\033[30m"
#define COLOR_RED           "\033[31m"
#define COLOR_GREEN         "\033[32m"
#define COLOR_YELLOW        "\033[33m"
#define COLOR_BLUE          "\033[34m"
#define COLOR_MAGENTA       "\033[35m"
#define COLOR_CYAN          "\033[36m"
#define COLOR_WHITE         "\033[37m"

// Bright foreground colors
#define COLOR_BRIGHT_BLACK  "\033[90m"
#define COLOR_BRIGHT_RED    "\033[91m"
#define COLOR_BRIGHT_GREEN  "\033[92m"
#define COLOR_BRIGHT_YELLOW "\033[93m"
#define COLOR_BRIGHT_BLUE   "\033[94m"
#define COLOR_BRIGHT_MAGENTA "\033[95m"
#define COLOR_BRIGHT_CYAN   "\033[96m"
#define COLOR_BRIGHT_WHITE  "\033[97m"

// Combined styles for specific elements
#define COLOR_HEADER        COLOR_BOLD COLOR_CYAN
#define COLOR_PACKET_ID     COLOR_BOLD COLOR_YELLOW
#define COLOR_MAC           COLOR_BOLD COLOR_MAGENTA
#define COLOR_IP            COLOR_BOLD COLOR_GREEN
#define COLOR_PORT          COLOR_BOLD COLOR_BLUE
#define COLOR_PROTOCOL      COLOR_BOLD COLOR_CYAN
#define COLOR_FLAGS         COLOR_BOLD COLOR_RED
#define COLOR_TIMESTAMP     COLOR_DIM COLOR_WHITE
#define COLOR_SEPARATOR     COLOR_BRIGHT_BLACK
#define COLOR_ERROR         COLOR_BOLD COLOR_RED
#define COLOR_SUCCESS       COLOR_BOLD COLOR_GREEN
#define COLOR_WARNING       COLOR_BOLD COLOR_YELLOW
#define COLOR_LABEL         COLOR_BOLD COLOR_WHITE
#define COLOR_VALUE         COLOR_WHITE
#define COLOR_HEX           COLOR_BRIGHT_BLUE
#define COLOR_ASCII         COLOR_BRIGHT_GREEN

#endif // COLORS_H
