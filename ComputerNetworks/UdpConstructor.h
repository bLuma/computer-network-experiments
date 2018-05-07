#ifndef __UDPCONSTRUCTOR_H
#define __UDPCONSTRUCTOR_H

#include "ILayerConstructor.h"
#include "IPv4Constructor.h"
#include "udp.h"
#include "endian.h"

/**
  UdpConstructor
*/
class CN_DLLSPEC UdpConstructor : public ILayerConstructor
{
public:
    UdpConstructor() 
    {
    }

    void setSourcePort(uint16 port)
    {
        m_srcPort = port;
    }

    void setDestinationPort(uint16 port)
    {
        m_destPort = port;
    }

    void setChecksumCalculation(bool on)
    {
        m_checksum = on;
    }

    virtual bool isType(LayerType type) const
    {
        return type == LtUDP;
    }

    virtual MemBlock* construct(const MemBlock* upperLayers);

private:
    uint16 m_srcPort;
    uint16 m_destPort;
    bool m_checksum;
};

#endif
