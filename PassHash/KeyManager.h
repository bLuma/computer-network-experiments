#ifndef __KEYMANAGER_H
#define __KEYMANAGER_H

#include <types.h>
#include <map>

using namespace std;

typedef map<uint32, string> KeyMap;

/*
 Spravce klicu, umoznuje ukladat ruzna hesla dle keyId
*/
class CN_DLLSPEC KeyManager
{
public:
    void assign(uint32 keyId, string key);
    bool hasKey(uint32 keyId) const;
    string getKey(uint32 keyId) const;

private:
    KeyMap m_keys;
};

#endif
