#ifndef __ETHERNET_H
#define __ETHERNET_H

#include "types.h"

// higher layer protocol constants
#define ETH_TYPE_IPV4 uint16(0x0800)
#define ETH_TYPE_ARP  uint16(0x0806)
#define ETH_TYPE_IPV6 uint16(0x86DD)

// MAC addr length
#define ETH_MAC_LENGTH 6

// L2 ethernet header length
#define ETHERNET_HEADER_LENGTH (ETH_MAC_LENGTH * 2 + 2)

// common MAC addresses
#define ETH_MAC_BROADCAST MACAddress(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
#define ETH_MAC_NULL      MACAddress(0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

/*
 * MAC/HW address
 */
struct CN_DLLSPEC MACAddress {
    uint8 bytes[ETH_MAC_LENGTH];

    MACAddress() 
    { 
        bytes[0] = 0;
        bytes[1] = 0;
        bytes[2] = 0;
        bytes[3] = 0;
        bytes[4] = 0;
        bytes[5] = 0;
    }

    MACAddress(uint8 a, uint8 b, uint8 c, uint8 d, uint8 e, uint8 f)
    {
        bytes[0] = a;
        bytes[1] = b;
        bytes[2] = c;
        bytes[3] = d;
        bytes[4] = e;
        bytes[5] = f;
    }

    bool operator==(const MACAddress& other)
    {
        for (uint8 i = 0; i < ETH_MAC_LENGTH; i++)
            if (bytes[i] != other.bytes[i])
                return false;

        return true;
    }
};

/*
 * Ethernet frame
 */
struct CN_DLLSPEC EthernetFrame {
    MACAddress destination;
    MACAddress source;
    uint16 lenOrType;
};

#endif
