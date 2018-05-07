#include "RipConstructor.h"
#include "UdpConstructor.h"
#include "openssl/md5.h"

MemBlock* RipConstructor::construct(const MemBlock* upperLayers)
{
    if (!m_ripData)
        return NULL;

    MemBlock* block = new MemBlock(uint32(RIP_LENGTH(m_ripData)));

    // header
    RIPHeader* header = (RIPHeader*)block->getPtr();
    *header = m_ripData->getHeader();

    // entries
    RIPEntry* entries = (RIPEntry*)&(block->getPtr()[RIP_HEADER_LENGTH]);

    // authorization
    if (m_ripData->getAuthData().AFI)
    {
        *((RIPAuthentication*)entries) = m_ripData->getAuthData();

        convertHN(((RIPAuthentication*)entries)->AuType);
        //((RIPAuthentication*)entries)->AuType = convertHtoN(((RIPAuthentication*)entries)->AuType);

        switch (m_ripData->getAuthData().AuType)
        {
        case RIP_AUTHENTICATION_TYPE_IP_ROUTE:
            break;

        case RIP_AUTHENTICATION_TYPE_PASSWORD:
            break;

        case RIP_AUTHENTICATION_TYPE_MD5:
            RIPAuthenticationMD5* auth = (RIPAuthenticationMD5*)entries;

            auth->packetLen = convertHtoN(uint16(block->getSize() - (16 + 4)));
            convertHN(auth->sequenceNumber);
            break;
        }

        entries++;
    }

    // 
    RipEntries& entrieslist = m_ripData->getEntries();
    for (RipEntries::iterator it = entrieslist.begin(); it != entrieslist.end(); it++)
    {
        *entries = *it;

        convertHN(entries->AFI);
        convertHN(entries->routeTag);
        convertHN(entries->metric);
            
        entries++;
    }

    // authorization
    if (m_ripData->getAuthData().AFI)
    {
        if (m_ripData->getAuthData().AuType == RIP_AUTHENTICATION_TYPE_MD5)
        {
            uint8* trailer = (uint8*)entries;

            trailer[0] = 0xff;
            trailer[1] = 0xff;
            trailer[2] = 0x00;
            trailer[3] = 0x01;

            strncpy((char*)trailer + 4, m_ripData->getAuthKey().substr(0, 16).c_str(), 16);

            MD5_CTX md5;
            MD5_Init(&md5);
            MD5_Update(&md5, block->getPtr(), block->getSize());
            MD5_Final((uint8*)trailer + 4, &md5);
        }
    }

    // 
    if (m_lowerLayer && m_lowerLayer->isType(LtUDP))
    {
        // 
        ((UdpConstructor*)m_lowerLayer)->setDestinationPort(RIP_UDP_PORT);
        ((UdpConstructor*)m_lowerLayer)->setSourcePort(RIP_UDP_PORT);

        // 
        if (m_lowerLayer->getLowerLayer() && m_lowerLayer->getLowerLayer()->isType(LtIPv4))
        {
            IPv4Constructor* ipconst = (IPv4Constructor*)m_lowerLayer->getLowerLayer();

            switch (m_ripData->getHeader().version)
            {
            case 1:
                ipconst->setDestinationAddr(IPV4Address(255, 255, 255, 255));
                break;

            case 2:
                ipconst->setDestinationAddr(IPV4Address(224, 0, 0, 9));
                break;
            }
        }
    }

    return block;
}
