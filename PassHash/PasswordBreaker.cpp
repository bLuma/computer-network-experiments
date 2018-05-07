#include "PasswordBreaker.h"

PasswordBreaker::PasswordBreaker()
{
    m_dataPtr = NULL;
    m_keyPtr = NULL;
    m_hashPtr = NULL;

    m_dataSize = 0;
    m_keySize = 0;
    m_hashSize = 0;

    m_method = HashMD5;

    m_characters = "abcdefghijklmnopqrstuvwxyz0123456789";
    m_lastChar = '9';
}

void PasswordBreaker::crack()
{
#ifdef TEST_TIME
    m_ta = clock();
#endif

    switch (m_method)
    {
    case HashMD5:
        crackMd5();
        break;
    }

#ifdef TEST_TIME
    m_tb = clock();
    cout << "Cracking time: " << (float)((m_tb - m_ta) / (float)CLOCKS_PER_SEC) << " sec" << endl;
#endif
}

void PasswordBreaker::crackMd5()
{
    bool result;
    memset(m_keyPtr, 0, m_keySize);
    m_actualKeyLen = 0;

    do 
    {
        generateNextCombination();

        result = calculateMd5();
    } while (!result);
}

bool PasswordBreaker::calculateMd5()
{
    MD5_CTX md5context;
    unsigned char buffer[MD5_DIGEST_LENGTH];

    MD5_Init(&md5context);
    MD5_Update(&md5context, m_dataPtr, m_dataSize);
    MD5_Final(buffer, &md5context);

    return memcmp(buffer, m_hashPtr, m_hashSize) == 0;
}

void PasswordBreaker::generateNextCombination()
{
    register uint32 i = 0;
    register bool comp = false;

    do {
        if (i >= m_actualKeyLen) 
        {
            for (int32 j = m_keySize - 2; j >= 0; j--)
                m_keyPtr[j + 1] = m_keyPtr[j];

            m_keyPtr[0] = m_characters[0];

            m_actualKeyLen++;
            if (m_actualKeyLen == m_keySize) 
            {
                throw "Key overflow!";
                return;
            }
        }

        i++;
        uint32 v = m_actualKeyLen - i;
        uint8 lc = m_keyPtr[v];
        comp = (lc == (uint8)m_lastChar);

        if (comp) 
        {
            m_keyPtr[v] = m_characters[0];
        } 
        else 
        {
            m_keyPtr[v] = *(strchr(m_characters, lc) + 1);
        }
    } while (comp);
}
