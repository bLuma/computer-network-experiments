#ifndef __RIPCONSTRUCTOR_H
#define __RIPCONSTRUCTOR_H

#include "ILayerConstructor.h"
#include "IPv4Constructor.h"
#include "udp.h"
#include "rip.h"
#include "endian.h"

class CN_DLLSPEC RipConstructor : public ILayerConstructor
{
public:
    RipConstructor() 
    {
    }
    
    void setData(Rip* ripData)
    {
        m_ripData = ripData;
    }

    virtual bool isType(LayerType type) const
    {
        return type == LtRIP;
    }

    virtual MemBlock* construct(const MemBlock* upperLayers);

private:
    Rip* m_ripData;
};

#endif
