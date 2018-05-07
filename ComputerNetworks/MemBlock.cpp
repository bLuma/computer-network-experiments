#include "MemBlock.h"

MemBlock::~MemBlock()
{
    if (m_ptr && m_delete)
    {
        delete[] m_ptr;

        m_ptr = NULL;
        m_size = 0;
    }
}

void MemBlock::prepend(MemBlock* memblock)
{
    if (!memblock || !memblock->m_size)
        return;

    uint8* newPtr = new uint8[m_size + memblock->m_size];

    memcpy(newPtr, memblock->m_ptr, memblock->m_size);
    memcpy(newPtr + memblock->m_size, m_ptr, m_size);

    delete[] m_ptr;
    m_ptr = newPtr;
    m_size = m_size + memblock->m_size;
}
