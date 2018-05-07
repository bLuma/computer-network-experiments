#ifndef __ENDIAN_H
#define __ENDIAN_H
/*
Endian conversion functions
*/

#include "types.h"

/// Converts value from network byte order to host order
template<typename T>
CN_DLLSPEC T convertNtoH(T value);

/// Converts value from host byte order to network order
template<typename T>
CN_DLLSPEC T convertHtoN(T value);

template<typename T>
CN_DLLSPEC void convertHN(T& value);

#endif
