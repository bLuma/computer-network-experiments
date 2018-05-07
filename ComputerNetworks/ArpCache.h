#ifndef __ARPCACHE_H
#define __ARPCACHE_H

#include "types.h"
#include "ethernet.h"
#include "ipv4.h"
#include "toolkit.h"
#include <map>
#include <iostream>

typedef map<uint32, MACAddress> ArpMap;

class CN_DLLSPEC ArpCache
{
public:

    void addRequest(const IPV4Address& addr);
    bool isRequested(const IPV4Address& addr);

    void add(const IPV4Address& addr, const MACAddress& hwAddr);
    
    MACAddress getMAC(const IPV4Address& addr);

    void print(ostream& os)
    {
        for (ArpMap::iterator it = m_map.begin(); it != m_map.end(); it++)
        {
            os << convertIPToStr(*(const IPV4Address*)&it->first) << " - " << convertMacToStr(it->second);
            os << endl;
        }
    }

private:
    ArpMap m_map;
};

#endif
