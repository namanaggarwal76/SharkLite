# SharkLite 

## Description
C-Shark is a terminal-based network packet sniffer built using libpcap. It captures and analyzes network packets in real-time, providing detailed layer-by-layer dissection of Ethernet, IP (v4/v6), ARP, TCP, and UDP protocols. Think of it as a lightweight, command-line alternative to Wireshark.

## Features
- **Interface Discovery**: Automatically detects and lists all available network interfaces
- **Real-time Packet Capture**: Capture and display packets as they flow through the network
- **Layer-by-Layer Analysis**: 
  - Layer 2 (Ethernet): MAC addresses and EtherType
  - Layer 3 (Network): IPv4, IPv6, and ARP protocol details
  - Layer 4 (Transport): TCP and UDP with port identification
  - Layer 7 (Application): Payload hex dump with protocol identification
- **Packet Filtering**: Filter by HTTP, HTTPS, DNS, ARP, TCP, or UDP
- **Session Storage**: Store up to 10,000 packets from the last capture session
- **Detailed Inspection**: In-depth analysis of individual packets with full hex dumps
- **Graceful Controls**: Ctrl+C to stop capture, Ctrl+D to exit

## Project Structure
```
SharkLite/
├── Makefile           # Build configuration
├── README.md          # This file
├── cshark.h           # Main header with data structures
├── colors.h           # ANSI color codes for terminal output
├── interface.h/c      # Network interface discovery
├── parser.h/c         # Packet parsing logic
├── display.h/c        # Output formatting and colorized display
├── filter.h/c         # Packet filtering
├── capture.h/c        # Packet capture engine
├── storage.h/c        # Session storage management
└── main.c             # Main program entry point
```

## Prerequisites
- Linux operating system
- GCC compiler
- libpcap development library

## How to Build

Install libpcap-dev first
```bash
sudo apt-get install libpcap-dev
```

Simply run make in the project directory:
```bash
make
```

This will compile all source files and create the `cshark` executable.

To clean build artifacts:
```bash
make clean
```

## How to Run
C-Shark requires root privileges to access network interfaces. Run with sudo:
```bash
sudo ./cshark
```

## Usage Guide

### 1. Interface Selection
When you start C-Shark, it will automatically scan and display all available network interfaces. Select the one you want to monitor.

### 2. Main Menu Options
- **Option 1**: Start Sniffing (All Packets) - Captures all packets without filtering
- **Option 2**: Start Sniffing (With Filters) - Apply protocol-specific filters
- **Option 3**: Inspect Last Session - Review captured packets in detail
- **Option 4**: Exit C-Shark - Cleanup and exit

### 3. Capturing Packets
- Press **Ctrl+C** to stop capture and return to the main menu
- Press **Ctrl+D** to exit the program at any time

### 4. Packet Inspection
After capturing packets, select Option 3 to view the session summary. Enter a packet ID to see detailed analysis including:
- All protocol headers with decoded fields
- TCP flags, sequence numbers, port names
- Full hex dump of the entire packet frame
- Payload data in hex and ASCII format

## Implementation Highlights

### Modular Design
The code is organized into separate modules for maintainability:
- **Interface module**: Device discovery using pcap_findalldevs()
- **Parser module**: Multi-layer packet dissection
- **Display module**: Formatted output with hex dumps and colorized terminal output
- **Filter module**: BPF filter generation and packet matching
- **Capture module**: pcap_loop integration with signal handling
- **Storage module**: Dynamic memory management for packet storage
- **Colors module**: ANSI color codes for enhanced readability

### Protocol Support
- **Ethernet**: Full MAC address and EtherType decoding
- **IPv4**: All header fields including flags, TTL, protocol identification
- **IPv6**: Next header, hop limit, traffic class, flow label
- **ARP**: Request/reply identification, hardware and protocol addresses
- **TCP**: Flags, sequence/ack numbers, window size, port names
- **UDP**: Length, checksum, port identification
- **Application Layer**: HTTP, HTTPS, DNS protocol identification

### Memory Management
- Proper allocation and deallocation of packet buffers
- Session cleanup between capture runs
- Maximum packet limit to prevent memory exhaustion

## Testing Recommendations
- Use personal hotspot for predictable traffic patterns
- Test on localhost (lo interface) for controlled environment
- Use Wireshark alongside for verification
- Try various filters to test filtering logic
- Capture different protocol types (DNS queries, HTTP requests, ARP)