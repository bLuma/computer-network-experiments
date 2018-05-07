#include "EthernetConstructor.h"

MemBlock* EthernetConstructor::construct(const MemBlock* upperLayers) 
{
    MemBlock* block = new MemBlock(ETHERNET_HEADER_LENGTH);

    EthernetFrame* eth = (EthernetFrame*)block->getPtr();

    eth->source = m_sourceAddr;
    eth->destination = m_destinationAddr;
    eth->lenOrType = convertHtoN(m_typeOrLen);

    return block;
}
