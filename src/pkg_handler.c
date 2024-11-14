//=============================================================================
//    This file is part of mocd EtherWatch, a forensics basic toolkit.
//    Copyright (C) 2024 Guilherme Oliveira Santos
//    This is free software: you can redistribute it and/or modify it
//    under the terms of the GNU GPL3 or any later version.
//=============================================================================

//=============================================================================
// INCLUDES
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>

#include <arpa/inet.h> // inet_ntoa
#include <unistd.h>
#include <stdint.h>

#include "../include/pkg_handler.h"
#include "../include/debug.h"

//=============================================================================
// DEFINES
//=============================================================================

/* no need to import <netinet/ether.h> */
#define ETH_P_ALL	0x0003		    // Every packet 
#define ETH_P_IP    0x0800          // IPv4 protocol
#define ETH_ALEN    0X0006          // Ether address len (6 bytes for MAC)

#define IPV4_STRING_LEN 16
#define SOCKET_BUFFER_SIZE UINT16_MAX + 1

//=============================================================================
// ENUMS
//=============================================================================

typedef enum {
    HOPOPT     = 0x00,   // IPv6 Hop-by-Hop Option
    ICMP       = 0x01,   // Internet Control Message Protocol
    IGMP       = 0x02,   // Internet Group Management Protocol
    GGP        = 0x03,   // Gateway-to-Gateway Protocol
    IP_IN_IP   = 0x04,   // IP in IP (encapsulation)
    TCP        = 0x06,   // Transmission Control Protocol
    UDP        = 0x11,   // User Datagram Protocol
    IPV6       = 0x29,   // IPv6 encapsulation
    ROUTING    = 0x2B,   // IPv6 Routing header
    FRAGMENT   = 0x2C,   // IPv6 Fragment header
    GRE        = 0x2F,   // Generic Routing Encapsulation
    ESP        = 0x32,   // Encapsulating Security Payload
    AH         = 0x33,   // Authentication Header
    ICMPV6     = 0x3A,   // ICMP for IPv6
    NONE       = 0x3B,   // IPv6 No Next Header
    DSTOPTS    = 0x3C,   // IPv6 Destination Options
    EIGRP      = 0x58,   // Enhanced Interior Gateway Routing Protocol
    OSPF       = 0x59,   // Open Shortest Path First
    MTP        = 0x5C,   // Multicast Transport Protocol
    ENCAP      = 0x62,   // Encapsulation Header
    PIM        = 0x67,   // Protocol Independent Multicast
    COMP       = 0x6C,   // Compression Header Protocol
    SCTP       = 0x84,   // Stream Control Transmission Protocol
    UDPLITE    = 0x88,   // UDP-Lite
    RAW        = 0xFF    // Raw IP packets
} IPProtocols;

//=============================================================================
// STRUCTS
//=============================================================================

struct ethhdr {
    uint8_t h_dest[ETH_ALEN];    // Dest MAC address
    uint8_t h_source[ETH_ALEN];  // Sre MAC address
    uint16_t h_proto;            // Protocol type (e.g., ETH_P_IP for IPv4)
};

// IPv4 header
struct iphdr {
    uint8_t ihl:4;           // Header length
    uint8_t version:4;       // Version (IPv4)
    uint8_t tos;             // Type of service
    uint16_t tot_len;        // Total length
    uint16_t id;             // Identification
    uint16_t frag_off;       // Fragment offset
    uint8_t ttl;             // Time to live
    uint8_t protocol;        // Protocol (e.g., TCP/UDP)
    uint16_t check;          // Header checksum
    uint32_t saddr;          // Source address
    uint32_t daddr;          // Destination address
};

// TCP header
struct tcphdr {
    uint16_t source;         // Source port
    uint16_t dest;           // Destination port
    uint32_t seq;            // Sequence number
    uint32_t ack_seq;        // Acknowledgment number
    uint8_t res1:4;          // Reserved bits
    uint8_t doff:4;          // Data offset
    uint8_t flags;           // Control flags
    uint16_t window;         // Window size
    uint16_t check;          // Checksum
    uint16_t urg_ptr;        // Urgent pointer
};

// UDP header
struct udphdr {
    uint16_t source;         // Source port
    uint16_t dest;           // Destination port
    uint16_t len;            // Datagram length
    uint16_t check;          // Checksum
};

// Session to be saved in a database to future analysis
typedef struct {
    int32_t src_port;
    int32_t dest_port;
    char src_ip[IPV4_STRING_LEN];
    char dest_ip[IPV4_STRING_LEN];
    char protocol[INT8_MAX];
} Session;

//=============================================================================
// GLOBAL VARS
//=============================================================================

static Session g_session; 

//=============================================================================
// FUNCIONS
//=============================================================================

static void parsePackage(uint8_t * buffer, int32_t buffer_size);

static void parseTcpHeader(uint8_t * buffer);
static void parseUdpHeader(uint8_t * buffer);
static void parseUknownHeader(uint8_t protocol);

static void handleSession(void);             // void pram because g_session

void * startPackageCapture(void*) {
    /* init the global var g_session */
    memset(g_session.dest_ip, '\0', IPV4_STRING_LEN);
    memset(g_session.src_ip, '\0', IPV4_STRING_LEN);

    struct sockaddr saddr;
    uint8_t * buffer = (uint8_t*)malloc(SOCKET_BUFFER_SIZE);
    
    int32_t sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));    
    if (sock < 0) {
        DEBUG_PRINT(RED_DEBUG, "SOCKET CREATION FAILED");
        return;
    }

    while (1) {
        socklen_t saddr_len = sizeof(saddr);
        int32_t data_size = recvfrom(sock, buffer, SOCKET_BUFFER_SIZE, 0,
            &saddr, &saddr_len);
        if (data_size < 0){
            DEBUG_PRINT(RED_DEBUG, "ERROR CAPTURING DATA");
            break;
        }
        parsePackage(buffer, data_size);   
        handleSession(); 
    }

    close(sock);
    free(buffer);
}

static void parsePackage(uint8_t * buffer, int32_t buffer_size) {
    struct iphdr *ip_header = (struct iphdr *)
                            (buffer + sizeof(struct ethhdr));
    
    strncpy(g_session.src_ip,
            inet_ntoa(*(struct in_addr *)&ip_header->saddr),
            IPV4_STRING_LEN - 1);  

    strncpy(g_session.dest_ip,
            inet_ntoa(*(struct in_addr *)&ip_header->daddr),
            IPV4_STRING_LEN - 1);

    switch (ip_header->protocol) {
        case ICMP:     break;
        case TCP:      parseTcpHeader(buffer); break;
        case UDP:      parseUdpHeader(buffer); break;
        case IPV6:     break;
        case ICMPV6:   break;
        
        // TODO: Add more cases 
        default:       parseUknownHeader(ip_header->protocol); break;
    }
}

static void parseTcpHeader(uint8_t * buffer){
    struct iphdr *ip_header = (struct iphdr *)
                            (buffer + sizeof(struct ethhdr));
    
    struct tcphdr * tcp_header = (struct tcphdr *)
                            (buffer + ip_header->ihl * 4 + 
                            sizeof(struct ethhdr));

    g_session.dest_port = ntohs(tcp_header->dest);
    g_session.src_port = ntohs(tcp_header->source);
    strcpy(g_session.protocol, "TCP/IP");
}

static void parseUdpHeader(uint8_t * buffer) {
    struct iphdr *ip_header = (struct iphdr *)
                            (buffer + sizeof(struct ethhdr));
    
    struct udphdr * udp_header = (struct udphdr *)
                            (buffer + ip_header->ihl * 4) + 
                            sizeof(struct ethhdr);

    g_session.src_port  = (int32_t)ntohs(udp_header->source);
    g_session.dest_port = (int32_t)ntohs(udp_header->dest);
    strcpy(g_session.protocol, "UDP/IP");

}

static void handleSession(void) {
    DEBUG_PRINT(CYAN_DEBUG, "PACKAGE");
    printf( " ├── Source Ip: %s \n"
            " └─  Dest Ip: %s \n"
            " ├── Source port: %d \n"
            " └─  Dest port: %d \n"
            " ├── Protocol: %s \n",
            g_session.src_ip,
            g_session.dest_ip,
            g_session.src_port,
            g_session.dest_port,
            g_session.protocol
    );
}

static void parseUknownHeader(uint8_t protocol) {
    g_session.dest_port = -1;
    g_session.src_port = -1;
    
    sprintf(g_session.protocol, "Unknown: [%u]", protocol);
}