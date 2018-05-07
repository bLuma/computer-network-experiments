#ifndef __DEFAULTINFORMATION_H
#define __DEFAULTINFORMATION_H

#include "types.h"
#include "ethernet.h"
#include "ipv4.h"

class CN_DLLSPEC DefaultInformation
{
public:
    static MACAddress macAddr;
    static IPV4Address ipv4Addr;
};

#endif
