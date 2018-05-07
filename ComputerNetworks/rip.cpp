#include "rip.h"
#include "toolkit.h"
#include <openssl/md5.h>
#include <sstream>

void Rip::loadFromPacket(const MemBlock* packet)
{
    const uint8* begin = (const uint8*)packet->getPtr();

    m_header = *(const RIPHeader*)(begin);
    convertHN(m_header.mustBeZero);

    const RIPEntry* entries = (const RIPEntry*)(begin + RIP_HEADER_LENGTH);
    uint32 entriesCount = (packet->getSize() - RIP_HEADER_LENGTH) / RIP_ENTRY_LENGTH;

    if (entries->AFI == RIP_AFI_AUTH)
    {
        m_authData = *((const RIPAuthentication*)entries);
        convertHN(m_authData.AuType);

        switch (m_authData.AuType)
        {
        case RIP_AUTHENTICATION_TYPE_IP_ROUTE:
            break;

        case RIP_AUTHENTICATION_TYPE_PASSWORD:
            break;

        case RIP_AUTHENTICATION_TYPE_MD5:
            RIPAuthenticationMD5* auth = (RIPAuthenticationMD5*)&m_authData;

            convertHN(auth->packetLen);
            convertHN(auth->sequenceNumber);

            entriesCount--;
            break;
        }

        entries++;
        entriesCount--;
    }

    for (uint32 i = 0; i < entriesCount; i++)
    {
        RIPEntry entry = *entries;

        convertHN(entry.AFI);
        convertHN(entry.routeTag);
        convertHN(entry.metric);

        m_entries.push_back(entry);

        entries++;
    }

    if (m_authData.AFI && m_authData.AuType == RIP_AUTHENTICATION_TYPE_MD5)
    {
        const RIPAuthenticationMD5trailer* md5trailer = (const RIPAuthenticationMD5trailer*)entries;

        m_authKey = convertBinaryToHex(md5trailer->hash, RIP_MD5_LENGTH);
    }
}

bool Rip::testMd5Password(const RIPHeader* packet, uint32 packetSize, string password)
{
    uint8 calculatedHash[MD5_DIGEST_LENGTH];
    
    uint8* copy = new uint8[packetSize];
    memcpy(copy, packet, packetSize);

    uint8* passwordPosition = copy + packetSize - MD5_DIGEST_LENGTH;
    memset(passwordPosition, 0, MD5_DIGEST_LENGTH);

    strncpy((char*)passwordPosition, password.substr(0, 16).c_str(), MD5_DIGEST_LENGTH);

    MD5_CTX md5context;
    MD5_Init(&md5context);
    MD5_Update(&md5context, copy, packetSize);
    MD5_Final(calculatedHash, &md5context);

    delete[] copy;

    return memcmp(calculatedHash, (uint8*)packet + packetSize - MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH) == 0;
}
