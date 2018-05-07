#include "PacketParser.h"
#include <tcpip.h>
#include <toolkit.h>
#include <cstdlib>

void PacketParser::parse(const uint8* ptr, uint32 size)
{
    uint32 layer = 2;
    uint32 protocol = 0;
    const uint8* packetPtr = ptr;

    do
    {
        ParseNode* node = getParseTable();
        while (node && node->layer)
        {
            if (node->layer == layer && node->protocol == protocol)
            {
                packetPtr = (this->*node->function)(packetPtr, protocol);
                layer++;
                break;
            }

            node++;
        }

        if (!node || !node->layer || !packetPtr)
            break;

    } while (protocol != 0);
}

PacketParser::ParseNode* PacketParser::getParseTable()
{
    static ParseNode table[] = {
        {&PacketParser::parseEthernet, 2,               0},
        {&PacketParser::parseIPv4,     3,   ETH_TYPE_IPV4},
        {&PacketParser::parseIPv6,     3,   ETH_TYPE_IPV6},
        {&PacketParser::parseTCP,      4, IP_PROTOCOL_TCP},
        {&PacketParser::parseUDP,      4, IP_PROTOCOL_UDP},
        {NULL,                         0,               0}
    };

    return table;
}

const uint8* PacketParser::parseEthernet(const uint8* ptr, uint32& protocol)
{
    const EthernetFrame* frame = (EthernetFrame*)ptr;

    printf("# destination mac:  %s \n", convertMacToStr(frame->destination).c_str());
    printf("# source mac:  %s \n", convertMacToStr(frame->source).c_str());

    protocol = convertNtoH(frame->lenOrType);
    return ptr + ETHERNET_HEADER_LENGTH;
}

const uint8* PacketParser::parseIPv4(const uint8* ptr, uint32& protocol)
{
    const IPV4Header* ipheader = (const IPV4Header*)ptr;

    printf("# # IPv4 packet\n");
    printf("# # destination ip: %s \n", convertIPToStr(ipheader->destination).c_str());
    printf("# # source ip: %s \n", convertIPToStr(ipheader->source).c_str());
    printf("# # ttl: %u, identification: %u, fragment offset: %u, flags: %s \n", ipheader->ttl, convertNtoH(ipheader->id), convertNtoH(ipheader->getFragmentOffset()), ipheader->getFlagsStr().c_str());

    protocol = ipheader->protocol;
    return ptr + IPV4_HEADER_LENGTH(ipheader);
}

const uint8* PacketParser::parseIPv6(const uint8* ptr, uint32& protocol)
{
    const IPV6Header* ipheader = (const IPV6Header*)ptr;

    printf("# # IPv6 packet\n");
    printf("# # destination ip: %s \n", convertIPToStr(ipheader->destination).c_str());
    printf("# # source ip: %s \n", convertIPToStr(ipheader->source).c_str());
    printf("# # hop limit: %u, flow label: -- \n", ipheader->hopLimit);

    protocol = ipheader->nextHeader;
    return ptr + IPV6_HEADER_LENGTH;
}

const uint8* PacketParser::parseTCP(const uint8* ptr, uint32& protocol)
{
    const TCPHeader* tcpheader = (const TCPHeader*)ptr;

    printf("# # # TCP \n");
    printf("# # # destination port: %u \n", convertNtoH(tcpheader->destinationPort));
    printf("# # # source port: %u \n", convertNtoH(tcpheader->sourcePort));
    printf("# # # seq: %u, ack: %u \n", convertNtoH(tcpheader->sequenceNum), convertNtoH(tcpheader->ackNum));
    printf("# # # flags: %s \n", tcpheader->getFlags().c_str());

    protocol = convertNtoH(tcpheader->destinationPort);
    return ptr + TCP_HEADER_LENGTH(tcpheader);
}

const uint8* PacketParser::parseUDP(const uint8* ptr, uint32& protocol)
{
    const UDPHeader* udpheader = (const UDPHeader*)ptr;

    printf("# # # UDP \n");
    printf("# # # destination port: %u \n", convertNtoH(udpheader->destinationPort));
    printf("# # # source port: %u \n", convertNtoH(udpheader->sourcePort));

    protocol = convertNtoH(udpheader->destinationPort);
    return ptr + UDP_HEADER_LENGTH;
}
