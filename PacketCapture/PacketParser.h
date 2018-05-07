#ifndef __PACKETPARSER_H
#define __PACKETPARSER_H

#include <types.h>

class PacketParser
{
public:
    void parse(const uint8* ptr, uint32 size);

private:
    typedef const uint8* (PacketParser::*ParseFunction)(const uint8* ptr, uint32& protocol);

    struct ParseNode 
    {
        ParseFunction function;
        uint32 layer;
        uint32 protocol;
    };

    ParseNode* getParseTable();

    const uint8* parseEthernet(const uint8* ptr, uint32& protocol);
    const uint8* parseIPv4(const uint8* ptr, uint32& protocol);
    const uint8* parseIPv6(const uint8* ptr, uint32& protocol);
    const uint8* parseTCP(const uint8* ptr, uint32& protocol);
    const uint8* parseUDP(const uint8* ptr, uint32& protocol);
};

#endif
