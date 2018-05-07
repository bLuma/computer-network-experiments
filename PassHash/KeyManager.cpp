#include "KeyManager.h"

void KeyManager::assign(uint32 keyId, string key)
{
    KeyMap::const_iterator it = m_keys.find(keyId);
    if (it != m_keys.end())
        m_keys.erase(keyId);
 
    m_keys.insert(pair<uint32, string>(keyId, key));
}

bool KeyManager::hasKey(uint32 keyId) const
{
    return m_keys.find(keyId) != m_keys.end();
}

string KeyManager::getKey(uint32 keyId) const
{
    KeyMap::const_iterator it = m_keys.find(keyId);
    if (it == m_keys.end())
        return "";

    return it->second;
}
