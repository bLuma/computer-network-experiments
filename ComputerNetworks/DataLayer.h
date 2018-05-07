#ifndef __DATALAYER_H
#define __DATALAYER_H

#include "ILayerConstructor.h"

/*
  DataLayer represents abstract data layer
  Memory block is deleted after packet constrution!
*/
class DataLayer : public ILayerConstructor
{
public:
    DataLayer() : m_block(NULL) { }

    void setData(MemBlock* block)
    {
        m_block = block;
        m_randDataSize = 0;
    }

    MemBlock* getData() const
    {
        return m_block;
    }

    void setExactRandomDataSize(int32 size)
    {
        m_randDataSize = size;
    }

    void setMaxRandomDataSize(int32 size)
    {
        m_randDataSize = -size;
    }

    virtual bool isType(LayerType type) const
    {
        return false;
    }

    virtual MemBlock* construct(const MemBlock* upperLayers);

private:
    MemBlock* m_block;
    int32 m_randDataSize;
};

#endif
