#ifndef HEADER_H_
#define HEADER_H_

#include <stdint.h>

#define IPV4_ETHERTYPE 0x0800

#define ICMPV4_PROTOCOL 0x01

#define ICMPV4_REPLY 0x00
#define ICMPV4_ECHO 0x08

//
//
struct ethernet_header {
    uint8_t  dest_mac_address[6];
    uint8_t  src_mac_address[6];
    uint16_t ethertype;
} __attribute__((packed));

//
//
struct ipv4_header {
    uint8_t  version : 4;
    uint8_t  ihl : 4;
    uint8_t  tos;
    uint16_t length;
    uint16_t identification;
    uint16_t fragmentation_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ipv4_address[4];
    uint8_t  dest_ipv4_address[4];
} __attribute__((packed));

//
//
struct icmpv4_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint8_t  data[];
} __attribute__((packed));

//
//
struct ping_header {
    struct ethernet_header ethernet_hdr;
    struct ipv4_header     ipv4_hdr;
    struct icmpv4_header   icmpv4_hdr;
} __attribute__((packed));

#endif
