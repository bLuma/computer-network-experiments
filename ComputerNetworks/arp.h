#ifndef __ARP_H
#define __ARP_H

#include "types.h"

#include "ethernet.h"
#include "ipv4.h"

#define ARP_HW_TYPE_ETHERNET  uint16(1)
#define ARP_PROTOCOL_IPV4     uint16(ETH_TYPE_IPV4)

#define ARP_OPERATION_REQUEST uint16(1)
#define ARP_OPERATION_REPLY   uint16(2)

#define ARP_HEADER_LENGTH     (2+2+1+1+2)
#define ARP_ETH_IPV4_LENGTH   (ETH_MAC_LENGTH * 2 + IPV4_ADDR_LENGTH * 2)

struct CN_DLLSPEC ARPHeader {
    uint16 hwType;
    uint16 protocolType;
    uint8 hwLen;
    uint8 protocolLen;
    uint16 operation;
};

struct CN_DLLSPEC ARPEthernetIPV4 {
    MACAddress sourceHwAddr;
    IPV4Address sourceProtocolAddr;
    MACAddress targetHwAddr;
    IPV4Address targetProtocolAddr;
};

#endif
