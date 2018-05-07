#include "DataLayer.h"

MemBlock* DataLayer::construct(const MemBlock* upperLayers)
{
    if (!m_block)
    {
        uint32 size = m_randDataSize;

        if (!m_randDataSize)
            size = 256;
        else if (m_randDataSize < 0)
            size = rand() % (-m_randDataSize);

        return new MemBlock(size);
    }

    MemBlock* copy = new MemBlock(m_block->getSize());
    memcpy(copy->getPtr(), m_block->getPtr(), m_block->getSize());

    return copy;
}
