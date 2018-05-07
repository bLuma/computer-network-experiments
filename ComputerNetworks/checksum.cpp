#include "checksum.h"

uint16 calculateChecksum(const MemBlock* memblock)
{
    return calculateChecksum(memblock->getPtr(), memblock->getSize());
}

uint16 calculateChecksum(const uint8* data, uint32 size) 
{
    uint32 value = 0;

    const uint16* ptr = (const uint16*)data;
    for (uint32 i = 0; i + 1 < size; i += 2)
    {
        value += (*ptr);

        ptr++;
    }

    if (size % 2 == 1)
    {
        const uint8* lastByte = (const uint8*)(ptr);
        value += uint16(*lastByte);
    }

    while (value >> 16) 
    {
        value = (value & 0xFFFF) + (value >> 16);
    }

    value = ~value;

    return (uint16(value & 0xFFFF));
}
