#ifndef __ARPCONSTRUCTOR_H
#define __ARPCONSTRUCTOR_H

#include "ILayerConstructor.h"
#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "endian.h"

class CN_DLLSPEC ArpConstructor : public ILayerConstructor
{
public:
    ArpConstructor() 
    {
        m_request = true;
    }

    void setRequest() { m_request = true;  }
    void setReply()   { m_request = false; }

    void setSourceHwAddr(MACAddress addr) { m_sourceHwAddr = addr; }
    void setSourceProtoAddr(IPV4Address addr) { m_sourceProtoAddr = addr; }
    void setDestinationHwAddr(MACAddress addr) { m_destinationHwAddr = addr; }
    void setDestinationProtoAddr(IPV4Address addr) { m_destinationProtoAddr = addr; }

    virtual bool isType(LayerType type) const
    {
        return type == LtARP;
    }

    virtual MemBlock* construct(const MemBlock* upperLayers);

private:
    MACAddress m_sourceHwAddr;
    MACAddress m_destinationHwAddr;
    IPV4Address m_sourceProtoAddr;
    IPV4Address m_destinationProtoAddr;
    bool m_request;
};

#endif
