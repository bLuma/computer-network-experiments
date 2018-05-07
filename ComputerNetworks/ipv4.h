#ifndef __IPV4_H
#define __IPV4_H

#include "types.h"
#include "endian.h"
#include "checksum.h"
#include "ethernet.h"

// higher layer protocol constant
#define IP_PROTOCOL_ICMP  1
#define IP_PROTOCOL_IGMP  2
#define IP_PROTOCOL_TCP   6
#define IP_PROTOCOL_UDP  17
#define IP_PROTOCOL_OSPF 89

// IPv4 header length
#define IPV4_HEADER_LENGTH(headerPtr) ((headerPtr)->getHeaderLength())

// IPv4 address length
#define IPV4_ADDR_LENGTH 4

// common IPv4 addresses
#define IPV4_ADDR_BROADCAST IPV4Address(0xff, 0xff, 0xff, 0xff)
#define IPV4_ADDR_NULL      IPV4Address(0x00, 0x00, 0x00, 0x00)

enum CN_DLLSPEC IPv4Flags
{
    MF = 0,
    DF,
    Reserved
};

/*
  IPv4 address
*/
struct CN_DLLSPEC IPV4Address {
    union {
        uint32 address;
        uint8 bytes[IPV4_ADDR_LENGTH];
    };

    IPV4Address() 
    {
        address = 0;
    }

    IPV4Address(uint8 a, uint8 b, uint8 c, uint8 d)
    {
        bytes[0] = a;
        bytes[1] = b;
        bytes[2] = c;
        bytes[3] = d;
    }

    IPV4Address(uint32 addr) : address(addr) {}

    /*
      Gets class of IP address. Value 0 equals to class "A".
    */
    uint8 getClassId() const {
        #define IPV4_IS_CLASS(firstByte, shouldBe) (((firstByte) & (shouldBe)) == (shouldBe))
        
        if (IPV4_IS_CLASS(bytes[0], 0xf0))
            return 4;
        
        if (IPV4_IS_CLASS(bytes[0], 0xe0))
            return 3;

        if (IPV4_IS_CLASS(bytes[0], 0xc0))
            return 2;

        if (IPV4_IS_CLASS(bytes[0], 0x80))
            return 1;

        if (IPV4_IS_CLASS(bytes[0], 0x00))
            return 0;

        #undef IPV4_IS_CLASS
        return 255;
    }

    /*
      Creates MAC address for multicast IPv4 address
    */
    MACAddress getMulticastEthernetAddress() const {
        // 01:00:5e:7f:ff:ff.
        MACAddress addr;
        
        addr.bytes[0] = 0x01;
        addr.bytes[1] = 0x00;
        addr.bytes[2] = 0x5e;

        addr.bytes[3] = bytes[1] & 0x7f;
        addr.bytes[4] = bytes[2];
        addr.bytes[5] = bytes[3];

        return addr;
    }

    bool isBroadcast() const
    {
        return (*this) == IPV4_ADDR_BROADCAST;
    }

    bool operator==(const IPV4Address& other) const
    {
        if (address != other.address)
            return false;

        return true;
    }
};


/*
  IPv4 header (no options or padding)
*/
struct CN_DLLSPEC IPV4Header {
    uint8 verLen;
    uint8 tos;
    uint16 length;

    uint16 id;
    //uint8 flags : 3;
    //uint16 fragmentOffset : 13;
    uint8 flagsFragA;
    uint8 fragB;

    uint8 ttl;
    uint8 protocol;
    uint16 checksum;

    IPV4Address source;
    IPV4Address destination;

    uint8 getVersion() const {
        return verLen >> 4;
    }

    void setVersion(uint8 version) {
        verLen = (verLen & 0x0F) | (version << 4);
    }

    uint8 getHeaderLength() const {
        return (verLen & 0x0F) * 4;
    }

    void setHeaderLength(uint8 length) {
        length /= 4;

        verLen = (verLen & 0xF0) | length;
    }

    uint16 getFragmentOffset() const {
        //return (flagsFragmentOffset & 0x1FFF) >> 3;
        return fragB | ((flagsFragA & 0x1F) << 8);
    }

    uint8 getFlags() const {
        //return flagsFragmentOffset >> 13;
        return (flagsFragA & 0xE0) >> 5;
    }

    string getFlagsStr() const {
        string ret;

        if (hasFlag(MF)) ret += "MF ";
        if (hasFlag(DF)) ret += "DF ";
        if (hasFlag(Reserved)) ret += "Reserved ";

        return ret;
    }

    bool hasFlag(IPv4Flags flag) const {
        return (getFlags() & (1 << flag)) ? true : false;
    }

    uint16 calculateChecksum() const {
        IPV4Header copy = *this;
        copy.checksum = 0;

        return ::calculateChecksum((const uint8*)&copy, getHeaderLength());
    }
};

#endif
