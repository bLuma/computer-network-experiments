#ifndef __MEMBLOCK_H
#define __MEMBLOCK_H

#include "types.h"

/*
  Memory block
*/
class CN_DLLSPEC MemBlock
{
public:
    /// Constructor - allocates memory
    MemBlock(uint32 size)
    {
        if (size)
        {
            m_ptr = new uint8[size];
            memset(m_ptr, 0, size);
        }
        else
        {
            m_ptr = NULL;
        }

        m_size = size;
        m_delete = true;
    }

    /// Constructor - uses supplied memory
    MemBlock(uint8* ptr, uint32 size) : m_ptr(ptr), m_size(size), m_delete(true) { }

    /// Constructor - uses supplied memory
    MemBlock(uint8* ptr, uint32 size, bool deleteb) : m_ptr(ptr), m_size(size), m_delete(deleteb) { }

    ~MemBlock();

    /// Gets pointer to memory
    uint8* getPtr() {
        return m_ptr;
    }

    /// Gets pointer co constant memory
    const uint8* getPtr() const {
        return m_ptr;
    }

    /// Gets length of memory block
    uint32 getSize() const {
        return m_size;
    }

    /// Prepends current memory block with specified one
    void prepend(MemBlock* memblock);

private:
    /// Data pointer
    uint8* m_ptr;
    /// Data size (bytes)
    uint32 m_size;
    /// Should I delete memory block in destructor?
    bool m_delete;
};

#endif
