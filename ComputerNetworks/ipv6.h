#ifndef __IPV6_H
#define __IPV6_H

#include "types.h"

#define IPV6_HEADER_LENGTH (4+4+16+16)

#define IPV6_ADDR_LENGTH 16

struct CN_DLLSPEC IPV6Address {
    uint8 bytes[IPV6_ADDR_LENGTH];

    IPV6Address()
    {
        memset(bytes, 0, IPV6_ADDR_LENGTH);
    }

    IPV6Address(uint8* ptr)
    {
        memcpy(bytes, ptr, IPV6_ADDR_LENGTH);
    }
};

struct CN_DLLSPEC IPV6Header {
    uint32 mixed;
    uint16 length;
    uint8 nextHeader;
    uint8 hopLimit;
    IPV6Address source;
    IPV6Address destination;

    uint8 getVersion() const
    {
        return (mixed >> 4) & 0x0F;
    }

    uint8 getTrafficClass() const 
    {
        //return (mixed >> 4) & 0xFF;
        throw 0;
    }

    uint32 getFlowLabel() const
    {
        //return mixed >> (4+8);
        throw 0;
    }
};

#endif
