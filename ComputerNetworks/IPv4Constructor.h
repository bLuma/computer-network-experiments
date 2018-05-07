#ifndef __IPV4CONSTRUCTOR_H
#define __IPV4CONSTRUCTOR_H

#include "ILayerConstructor.h"
#include "EthernetConstructor.h"
#include "ethernet.h"
#include "ipv4.h"
#include "endian.h"

/**
  IPv4Constructor
*/
class CN_DLLSPEC IPv4Constructor : public ILayerConstructor
{
public:
    IPv4Constructor() 
    {
        m_ttl = 255;
    }

    void setSourceAddr(IPV4Address source) 
    {
        m_sourceAddr = source;
    }

    IPV4Address getSourceAddr() const
    {
        return m_sourceAddr;
    }

    void setDestinationAddr(IPV4Address destination)
    {
        m_destinationAddr = destination;
    }

    IPV4Address getDestinationAddr() const
    {
        return m_destinationAddr;
    }

    void setUpperProtocol(uint8 protocol)
    {
        m_protocol = protocol;
    }

    void setTTL(uint8 ttl)
    {
        m_ttl = ttl;
    }

    virtual bool isType(LayerType type) const
    {
        return type == LtIPv4;
    }

    virtual MemBlock* construct(const MemBlock* upperLayers);

private:
    IPV4Address m_sourceAddr;
    IPV4Address m_destinationAddr;
    uint8 m_protocol;
    uint8 m_ttl;
};

#endif
