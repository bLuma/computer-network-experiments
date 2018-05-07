#include "ArpCache.h"

void ArpCache::addRequest(const IPV4Address& addr)
{
    m_map.insert(pair<uint32, MACAddress>(*(uint32*)addr.bytes, ETH_MAC_NULL));
}

bool ArpCache::isRequested(const IPV4Address& addr)
{
    ArpMap::iterator it = m_map.find(*(uint32*)addr.bytes);
    if (it == m_map.end())
        return false;

    return it->second == ETH_MAC_NULL;
}

void ArpCache::add(const IPV4Address& addr, const MACAddress& hwAddr)
{
    ArpMap::iterator it = m_map.find(*(uint32*)addr.bytes);
    if (it == m_map.end())
    {
        m_map.insert(pair<uint32, MACAddress>(*(uint32*)addr.bytes, hwAddr));
    }
    else
    {
        it->second = hwAddr;
    }
}

MACAddress ArpCache::getMAC(const IPV4Address& addr)
{
    ArpMap::iterator it = m_map.find(*(uint32*)addr.bytes);
    if (it == m_map.end())
        return ETH_MAC_NULL;

    return it->second;
}
