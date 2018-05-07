#ifndef __PASSWORDBREAKER_H
#define __PASSWORDBREAKER_H

#define TEST_TIME

#include <types.h>
#include <openssl/md5.h>
#include <cstring>

#ifdef TEST_TIME
#include <time.h>
#include <iostream>
using namespace std;
#endif

enum HashMethod
{
    HashMD5
};

/*
 Vychozi trida pro prolomeni hesla, pouziva brute-force metodu.
 Z dat je vypocten zvoleny hash a porovnan s nastavenym hashem.
 Metoda setKey nastavuje na kterou pozici je ulozeno vygenerovane
 heslo.
*/
class CN_DLLSPEC PasswordBreaker
{
public:
    PasswordBreaker();

    void setData(uint8* data, uint32 size)
    {
        m_dataPtr = data;
        m_dataSize = size;
    }

    void setKey(uint8* key, uint32 size)
    {
        m_keyPtr = key;
        m_keySize = size;
    }

    void setHash(uint8* hash, uint32 size)
    {
        m_hashPtr = hash;
        m_hashSize = size;
    }

    void setMethod(HashMethod method)
    {
        m_method = method;
    }

    uint8* getData()
    {
        return m_dataPtr;
    }

    const uint32 getDataSize() const
    {
        return m_dataSize;
    }

    uint8* getHash()
    {
        return m_hashPtr;
    }

    virtual void crack();

private:
    void crackMd5();
    inline bool calculateMd5();
    inline void generateNextCombination();

    uint8* m_dataPtr;
    uint32 m_dataSize;

    uint8* m_keyPtr;
    uint32 m_keySize;

    uint8* m_hashPtr;
    uint32 m_hashSize;

    uint32 m_actualKeyLen;

    HashMethod m_method;

    const char* m_characters;
    char m_lastChar;

#ifdef TEST_TIME
    clock_t m_ta, m_tb;
#endif
};

#endif
