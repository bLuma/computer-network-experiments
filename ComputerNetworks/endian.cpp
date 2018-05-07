#include "endian.h"

template<typename T>
T convertNtoH(T value)
{
#if CN_CURRENT_ENDIAN == CN_LITTLE_ENDIAN
    T converted = value;
    uint8* ptr = (uint8*)&converted;

    for (int i = 0; i < sizeof(T) / 2; i++)
    {
        std::swap(ptr[i], ptr[sizeof(T) - 1 - i]);
    }

    return converted;
#else
    return value;
#endif
}

template<>
uint8 CN_DLLSPEC convertNtoH(uint8 value)
{
    return value;
}

template CN_DLLSPEC uint16 convertNtoH(uint16 value);
template CN_DLLSPEC uint32 convertNtoH(uint32 value);

template<typename T>
T convertHtoN(T value)
{
#if CN_CURRENT_ENDIAN == CN_LITTLE_ENDIAN
    T converted = value;
    uint8* ptr = (uint8*)&converted;

    for (int i = 0; i < sizeof(T) / 2; i++)
    {
        std::swap(ptr[i], ptr[sizeof(T) - 1 - i]);
    }

    return converted;
#else
    return value;
#endif
}

template<>
uint8 CN_DLLSPEC convertHtoN(uint8 value)
{
    return value;
}

template CN_DLLSPEC uint16 convertHtoN(uint16 value);
template CN_DLLSPEC uint32 convertHtoN(uint32 value);

template<typename T>
void convertHN(T& value)
{
#if CN_CURRENT_ENDIAN == CN_LITTLE_ENDIAN
    T converted = value;
    uint8* ptr = (uint8*)&converted;

    for (int i = 0; i < sizeof(T) / 2; i++)
    {
        std::swap(ptr[i], ptr[sizeof(T) - 1 - i]);
    }

    value = converted;
#endif
}

template void CN_DLLSPEC convertHN(uint16& value);
template void CN_DLLSPEC convertHN(uint32& value);
