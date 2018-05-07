#ifndef __PLATFORM_H
#define __PLATFORM_H

#ifdef _MSC_VER

#ifdef CN_DLLEXPORT
#define CN_DLLSPEC __declspec(dllexport)
#else
#define CN_DLLSPEC __declspec(dllimport)
#endif

#else

#define CN_DLLSPEC /* */

#endif

// endianess constant
#define CN_LITTLE_ENDIAN 0
#define CN_BIG_ENDIAN 1

// endianess detection - TODO
#define CN_CURRENT_ENDIAN CN_LITTLE_ENDIAN

#endif
