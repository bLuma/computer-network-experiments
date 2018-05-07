#include "UdpConstructor.h"

MemBlock* UdpConstructor::construct(const MemBlock* upperLayers)
{
    MemBlock* block = new MemBlock(UDP_HEADER_LENGTH);

    UDPHeader* header = (UDPHeader*)block->getPtr();

    // header params
    header->sourcePort = convertHtoN(m_srcPort);
    header->destinationPort = convertHtoN(m_destPort);
    header->length = convertHtoN(uint16(UDP_HEADER_LENGTH + (upperLayers ? upperLayers->getSize() : 0)));
    header->checksum = 0;

    // checksum
    if (m_checksum)
    {
        if (m_lowerLayer && m_lowerLayer->isType(LtIPv4))
        {
            IPv4Constructor* ipc = (IPv4Constructor*)m_lowerLayer;

            IPV4Header pseudoHeader;
            pseudoHeader.source = ipc->getSourceAddr();
            pseudoHeader.destination = ipc->getDestinationAddr();

            header->checksum = header->calculateChecksum(pseudoHeader, upperLayers);
        }
        else if (m_lowerLayer && m_lowerLayer->isType(LtIPv6))
            throw "No IPv6 support yet";
    }

    // 
    if (m_lowerLayer && m_lowerLayer->isType(LtIPv4))
        ((IPv4Constructor*)m_lowerLayer)->setUpperProtocol(IP_PROTOCOL_UDP);

    return block;
}
