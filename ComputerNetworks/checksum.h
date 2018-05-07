#ifndef __CHECKSUM_H
#define __CHECKSUM_H

#include "MemBlock.h"

/*
  Checksum caclulation of:
   "one's complements of 16bit words one's complement sum"
  Used in IPv4, UDP, ICMP
*/

/// Calculates checksum from memblock
CN_DLLSPEC uint16 calculateChecksum(const MemBlock* memblock) ;
/// Calculates checksum from data pointer
CN_DLLSPEC uint16 calculateChecksum(const uint8* data, uint32 size);

#endif
