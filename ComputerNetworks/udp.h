#ifndef __UDP_H
#define __UDP_H

#include "types.h"
#include "ipv4.h"
#include "MemBlock.h"
#include "checksum.h"

#define UDP_HEADER_LENGTH (2+2+2+2)

struct UDP_Checksum_pseudo
{
    IPV4Address source;
    IPV4Address destination;
    uint8 zeros;
    uint8 protocol;
    uint16 udpLen;
    void* udpHeader;
};

struct CN_DLLSPEC UDPHeader 
{
    uint16 sourcePort;
    uint16 destinationPort;
    uint16 length;
    uint16 checksum;

    uint16 calculateChecksum(IPV4Header ipheader, const MemBlock* userData) const {
        MemBlock* block = new MemBlock(UDP_HEADER_LENGTH + 4 + 4 + 4 + (userData ? userData->getSize() : 0));

        UDP_Checksum_pseudo* pseudoHeader = (UDP_Checksum_pseudo*)block->getPtr();

        pseudoHeader->source = ipheader.source;
        pseudoHeader->destination = ipheader.destination;
        pseudoHeader->zeros = 0;
        pseudoHeader->udpLen = length;
        pseudoHeader->protocol = IP_PROTOCOL_UDP;
        
        UDPHeader* udpHeader = (UDPHeader*)&pseudoHeader->udpHeader;
        memcpy(udpHeader, this, UDP_HEADER_LENGTH);
        udpHeader->checksum = 0;

        if (userData)
            memcpy((uint8*)pseudoHeader + (UDP_HEADER_LENGTH + 4 + 4 + 4), userData->getPtr(), userData->getSize());

        uint16 checksum = ::calculateChecksum(block);

        delete block;

        return checksum;
    }
};

#endif
