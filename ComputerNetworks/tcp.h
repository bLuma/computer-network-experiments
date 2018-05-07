#ifndef __TCP_H
#define __TCP_H

#include "types.h"
#include "ipv4.h"

#define TCP_HEADER_LENGTH(headerPtr) ((headerPtr)->getDataOffset())

enum CN_DLLSPEC TcpFlags
{
    Fin = 0,
    Syn,
    Rst,
    Psh,
    Ack,
    Urg,
    Ece,
    Cwr
};

struct TCP_Checksum_pseudo
{
    IPV4Address source;
    IPV4Address destination;
    uint8 zeros;
    uint8 protocol;
    uint16 tcpLen;
    void* tcpHeader;
};

struct CN_DLLSPEC TCPHeader 
{
    uint16 sourcePort;
    uint16 destinationPort;
    uint32 sequenceNum;
    uint32 ackNum;
    uint8 dataOffsetReserved;
    uint8 flags;
    uint16 windowSize;
    uint16 checksum;
    uint16 urgentPointer;

    uint8 getDataOffset() const 
    {
        return (dataOffsetReserved >> 4) * 4;
    }

    void setDataOffset(uint8 value)
    {
        dataOffsetReserved = (dataOffsetReserved & 0x0F) | ((value / 4) << 4);
    }

    bool hasFlag(TcpFlags flag) const
    {
        return (flags & (1 << flag)) ? true : false;
    }

    void setFlag(TcpFlags flag)
    {
        flags |= (1 << flag);
    }

    void unsetFlag(TcpFlags flag)
    {
        flags &= ~(1 << flag);
    }

    string getFlags() const;

    uint16 calculateChecksum(IPV4Header ipheader, const MemBlock* userData) const
    {
        MemBlock* block = new MemBlock(TCP_HEADER_LENGTH(this) + (4+4+1+1+2) + (userData ? userData->getSize() : 0));

        TCP_Checksum_pseudo* pseudoHeader = (TCP_Checksum_pseudo*)block->getPtr();

        pseudoHeader->source = ipheader.source;
        pseudoHeader->destination = ipheader.destination;
        pseudoHeader->zeros = 0;
        pseudoHeader->tcpLen = convertHtoN(uint16(TCP_HEADER_LENGTH(this) + (userData ? userData->getSize() : 0)));
        pseudoHeader->protocol = IP_PROTOCOL_TCP;
        
        TCPHeader* tcpHeader = (TCPHeader*)&pseudoHeader->tcpHeader;
        memcpy(tcpHeader, this, TCP_HEADER_LENGTH(this));
        tcpHeader->checksum = 0;

        if (userData)
            memcpy((uint8*)pseudoHeader + (TCP_HEADER_LENGTH(this) + 4 + 4 + 4), userData->getPtr(), userData->getSize());

        uint16 checksum = ::calculateChecksum(block);

        delete block;

        return checksum;
    }
};

#endif
