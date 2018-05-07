#include "IPv4Constructor.h"

/// IPv4 header length without options
#define IP_HEADER_STANDARD_LENGTH 20

MemBlock* IPv4Constructor::construct(const MemBlock* upperLayers) 
{
    MemBlock* block = new MemBlock(IP_HEADER_STANDARD_LENGTH);

    IPV4Header* header = (IPV4Header*)block->getPtr();

    // header params
    header->setVersion(4);
    header->setHeaderLength(IP_HEADER_STANDARD_LENGTH);

    header->ttl = m_ttl;
    header->tos = 0;
    header->id = 0;
    header->flagsFragA = 0;
    header->fragB = 0;
    
    header->source = m_sourceAddr;
    header->destination = m_destinationAddr;
    header->protocol = m_protocol;

    // packet length
    header->length = convertHtoN(uint16(IPV4_HEADER_LENGTH(header) + (upperLayers ? upperLayers->getSize() : 0)));
    
    // checksum
    header->checksum = header->calculateChecksum();

    // 
    if (m_lowerLayer && m_lowerLayer->isType(LtEthernet))
    {
        EthernetConstructor* ec = (EthernetConstructor*)m_lowerLayer;

        ec->setTypeOrLen(ETH_TYPE_IPV4);
        
        if (ec->getDestinationAddr() == ETH_MAC_NULL)
        {
			// automatic set of multicast/broadcast address
            if (m_destinationAddr.getClassId() == 3)
            {
                ec->setDestinationAddr(m_destinationAddr.getMulticastEthernetAddress());
            } 
            else if (m_destinationAddr.isBroadcast())
            {
                ec->setDestinationAddr(ETH_MAC_BROADCAST);
            }
        }

    }

    return block;
}
