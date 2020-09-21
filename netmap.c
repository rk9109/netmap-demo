#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <netinet/ih.h>

#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "headers.h"

static void error_exit(const char** fmt, ...)
{
    va_list arglist;

    va_start(arglist, fmt);
    vfprintf(stderr, fmt, arglist);
    va_end(arglist);

    exit(EXIT_FAILURE);
}

static bool ping_select(const char* buf)
{
    struct ping_header* hdr = (struct ping_header*)buf;

    // ignore non-ipv4 packets
    switch (ntohs((hdr->ethernet_hdr).ethertype)) {
    case IPV4_ETHERTYPE:
        break;
    default:
        return false;
    }

    // ignore non-icmpv4 packets
    switch ((hdr->ipv4_hdr).protocol) {
    case ICMPV4_PROTOCOL:
        break;
    default:
        return false;
    }

    // ignore non-icmpv4 echo packets
    switch ((hdr->icmpv4_header).type) {
    case ICMPV4_ECHO:
        break;
    default:
        return false;
    }

    return true;
}

static void ping_response(const char* buf)
{
    struct ping_header* hdr = (struct ping_header*)buf;

    // swap source/destination MAC address
    for (int i = 0; i < 6; i++) {
        uint8_t tmp;
        uint8_t* dest = (hdr->ethernet_header).dest_mac_address;
        uint8_t* src = (hdr->ethernet_header).src_mac_address;

        tmp = dest[i];
        dest[i] = src[i];
        src[i] = tmp;
    }

    // swap source/destination IPV4 address
    for (int i = 0; i < 4; i++) {
        uint8_t tmp;
        uint8_t* dest = (hdr->ipv4_header).dest_ipv4_address;
        uint8_t* src = (hdr->ipv4_header).src_ipv4_address;

        tmp = dest[i];
        dest[i] = src[i];
        src[i] = tmp;
    }

    // TODO recalculate ipv4 checksum

    // update icmpv4 header
    (hdr->icmpv4_header).type = ICMPV4_REPLY;

    // TODO recalculate icmpv4 checksum
}

static void netmap_rx(struct nm_desc* nmd)
{
    uint16_t ri = nmd->first_rx_ring;
    uint16_t ti = nmd->first_tx_ring;

    // TODO document
    for (ri <= nmd->last_rx_ring && ti <= nmd->last_tx_ring) {
        uint32_t nrx, ntx;
        uint32_t rx_head, tx_head;
        struct netmap_ring* rx_ring;
        struct netmap_ring* tx_ring;

        // NETMAP_RXRING / NETMAP_TXRING are macros to get a netmap_ring
        // from a netmap_if
        rx_ring = NETMAP_RXRING(nmd->nifp, ri);
        tx_ring = NETMAP_TXRING(nmd->nifp, ti);

        // TODO document
        nrx = rx_ring->tail - rx_ring->head;
        if (nrx < 0)
            nrx += rx_ring->num_slots;
        else if (nrx == 0) {
            ri++;
            continue;
        }

        ntx = tx_ring->tail - tx_ring->head;
        if (ntx < 0)
            ntx += tx_ring->num_slots;
        else if (ntx == 0) {
            ti++;
            continue;
        }

        // TODO document
        rx_head = rx_ring->head;
        tx_head = tx_ring->head;
        for (; nrx > 0 && ntx > 0; nrx--, rx_head = nm_ring_next(rx_ring, rx_head)) {
            struct netmap_slot* rx_slot;
            struct netmap_slot* tx_slot;

            rx_slot = &(rx_ring->slot[rx_head]);
            tx_slot = &(tx_ring->slot[tx_head]);

            // NETMAP_BUF is a macro to get packet buffer associated to a
            // netmap_ring slot
            char* buf = NETMAP_BUF(rx_ring, rx_slot->buf_idx);

            if (!ping_select(buf)) {
                continue;
            }

            // TODO document
            ping_response(buf);

            // TODO document
            tx_slot->len = rx_slot->len;

            uint32_t tmp = tx_slot->buf_idx;
            tx_slot->buf_idx = rx_slot->buf_idx;
            rx_slot->buf_idx = tmp;
            rx_slot->flags |= NS_BUF_CHANGED;
            tx_slot->flags |= NS_BUF_CHANGED;

            tx_head = nm_ring_next(tx_ring, tx_head);
            ntx--;
        }

        rx_ring->head = rx_ring->cur = rxhead;
        tx_ring->head = tx_ring->cur = txhead;
    }
}

static void netmap_loop(const char** netmap_port)
{
    struct nm_desc* nmd;

    // TODO document
    nmd = nm_open(netmap_port, NULL, 0, NULL);
    if (nmd == NULL) {
        if (!errno) {
            error_exit("nm_open: invalid port %s\n");
        } else {
            error_exit("nm_open: %s\n", strerror(errno));
        }
    }

    for (;;) {
        int ret;
        struct pollfd pfd;

        pfd[0].fd = nmd->fd;
        pfd[0].events = POLLIN;

        ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            error_exit("poll: %s\n", strerror(errno));
        } else {
            // timeout
            continue;
        }

        // TODO document
        netmap_rx(nmd);
    }
}

static void usage()
{
    printf("Usage: TODO\n");

    exit(EXIT_SUCCESS);
}

int main(int argc, char** argv)
{
    netmap_loop("netmap:eth0");
}
