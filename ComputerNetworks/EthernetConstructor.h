#ifndef __ETHERNETCONSTRUCTOR_H
#define __ETHERNETCONSTRUCTOR_H

#include "ILayerConstructor.h"
#include "ethernet.h"
#include "endian.h"

class CN_DLLSPEC EthernetConstructor : public ILayerConstructor
{
public:
    EthernetConstructor() 
    {
        m_typeOrLen = 0;
    }

    EthernetConstructor(MACAddress sourceAddr, MACAddress destinationAddr, uint16 typeOrLen) :
      m_sourceAddr(sourceAddr), m_destinationAddr(destinationAddr), m_typeOrLen(typeOrLen) 
    { 
    }

    void setSourceAddr(MACAddress source) 
    {
        m_sourceAddr = source;
    }

    MACAddress getSourceAddr()
    {
        return m_sourceAddr;
    }

    void setDestinationAddr(MACAddress destination)
    {
        m_destinationAddr = destination;
    }

    MACAddress getDestinationAddr()
    {
        return m_destinationAddr;
    }

    void setTypeOrLen(uint16 typeOrLen)
    {
        m_typeOrLen = typeOrLen;
    }

    virtual bool isType(LayerType type) const
    {
        return type == LtEthernet;
    }

    virtual MemBlock* construct(const MemBlock* upperLayers);

private:
    MACAddress m_sourceAddr;
    MACAddress m_destinationAddr;
    uint16 m_typeOrLen;
};

#endif
