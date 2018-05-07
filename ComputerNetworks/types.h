#ifndef __TYPES_H
#define __TYPES_H

// visual studio
#ifdef _MSC_VER

// no warnings about unsecure or depreated function
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS

// needs to have dll-interface to be used by clients of class
#pragma warning (disable: 4251)

#endif

#include <cstdlib>
#include <string>
#include <vector>

#include "platform.h"

// std namespace
using namespace std;

// data types
typedef unsigned int   uint32;
typedef unsigned short uint16;
typedef unsigned char  uint8;

typedef int   int32;
typedef short int16;
typedef char  int8;

#endif
