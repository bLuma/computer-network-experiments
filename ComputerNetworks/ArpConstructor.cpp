#include "ArpConstructor.h"
#include "EthernetConstructor.h"

MemBlock* ArpConstructor::construct(const MemBlock* upperLayers)
{
    MemBlock* block = new MemBlock(ARP_HEADER_LENGTH + ARP_ETH_IPV4_LENGTH);

    ARPHeader* header = (ARPHeader*)block->getPtr();

    // header construction
    header->hwLen = ETH_MAC_LENGTH;
    header->hwType = convertHtoN(ARP_HW_TYPE_ETHERNET);
    header->protocolLen = IPV4_ADDR_LENGTH;
    header->protocolType = convertHtoN(ARP_PROTOCOL_IPV4);

    if (m_request)
        header->operation = convertHtoN(ARP_OPERATION_REQUEST);
    else
        header->operation = convertHtoN(ARP_OPERATION_REPLY);

    // 
    ARPEthernetIPV4* extended = (ARPEthernetIPV4*)&(block->getPtr()[ARP_HEADER_LENGTH]);

    extended->sourceHwAddr = m_sourceHwAddr;
    extended->sourceProtocolAddr = m_sourceProtoAddr;
    extended->targetHwAddr = m_destinationHwAddr;
    extended->targetProtocolAddr = m_destinationProtoAddr;

    // 
    if (m_lowerLayer && m_lowerLayer->isType(LtEthernet))
    {
        EthernetConstructor* ec = (EthernetConstructor*)m_lowerLayer;

        ec->setSourceAddr(m_sourceHwAddr);
        ec->setDestinationAddr(ETH_MAC_BROADCAST);
        
        ec->setTypeOrLen(ETH_TYPE_ARP);
    }

    return block;
}
