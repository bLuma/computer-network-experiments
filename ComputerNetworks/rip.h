#ifndef __RIP_H
#define __RIP_H

#include "types.h"
#include "ipv4.h"

// rip header length
#define RIP_HEADER_LENGTH (1+1+2)

// authorization types
#define RIP_AUTHENTICATION_TYPE_IP_ROUTE  uint16(1)
#define RIP_AUTHENTICATION_TYPE_PASSWORD  uint16(2)
#define RIP_AUTHENTICATION_TYPE_MD5       uint16(3)

// command types
#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_REPLY    2

// AFI values
#define RIP_AFI_IP    uint16(2)
#define RIP_AFI_AUTH  uint16(0xFFFF)

// rip UPD port
#define RIP_UDP_PORT  uint16(520)

// rip entry length
#define RIP_ENTRY_LENGTH  (sizeof(RIPEntry))

#define RIP_MD5_LENGTH 16

// rip packet length
#define RIP_LENGTH(ripData) ( \
    /* header */ \
    RIP_HEADER_LENGTH +  \
    /* size of routing entries */ \
    (ripData)->getEntries().size() * RIP_ENTRY_LENGTH + \
    /* authorization record */ \
    ((ripData)->getAuthData().AFI ? RIP_ENTRY_LENGTH : 0) + \
    /* MD5 appends another trailer to packet */ \
    ((ripData)->getAuthData().AFI && (ripData)->getAuthData().AuType == RIP_AUTHENTICATION_TYPE_MD5 ? 16+4 : 0) \
    )

/*
  RIP header
*/
struct CN_DLLSPEC RIPHeader
{
    uint8 command;
    uint8 version;
    uint16 mustBeZero;

    RIPHeader()
    {
        command = RIP_COMMAND_REPLY;
        version = 1;
        mustBeZero = 0;
    }
};

/*
  Routing entry
*/
struct CN_DLLSPEC RIPEntry
{
    uint16 AFI;
    uint16 routeTag;
    
    IPV4Address network;
    IPV4Address subnetmask;
    IPV4Address nextHop;

    uint32 metric;

    RIPEntry()
    {
        AFI = RIP_AFI_IP;
        routeTag = 0;
        metric = 0;
    }
};

/*
  Authentication
*/
struct CN_DLLSPEC RIPAuthentication
{
    uint16 AFI;
    uint16 AuType;

    uint8 dummy[(4+4+4+4)];

    RIPAuthentication()
    {
        AFI = 0;
    }

    string getKeyData() const
    {
        char copy[16 + 1];

        memcpy(copy, dummy, 16);
        copy[16] = '\0';

        return (char*)copy;
    }
};

/*
  MD5 auth
*/
struct CN_DLLSPEC RIPAuthenticationMD5
{
    uint16 AFI;    // must be 0xFFFF
    uint16 AuType; // RIP_AUTHENTICATION_TYPE_MD5

    uint16 packetLen;
    uint8 keyId;
    uint8 authDataLen;

    uint32 sequenceNumber;

    uint32 dummy1;
    uint32 dummy2;

    RIPAuthenticationMD5()
    {
        AFI = RIP_AFI_AUTH;
        AuType = RIP_AUTHENTICATION_TYPE_MD5;
        authDataLen = RIP_ENTRY_LENGTH;
        dummy1 = 0;
        dummy2 = 0;
    }
};

struct CN_DLLSPEC RIPAuthenticationMD5trailer
{
    uint16 AFI;
    uint16 AuType;

    uint8 hash[RIP_MD5_LENGTH];
};

// vektor of routing entries
typedef vector<RIPEntry> RipEntries;

/*
  RIP
*/
class CN_DLLSPEC Rip
{
public:
    Rip()
    {
        m_header.command = RIP_COMMAND_REPLY;
        m_header.version = 1;
        m_header.mustBeZero = 0;
        memset(&m_authData, 0, RIP_ENTRY_LENGTH);
    }

    void setVersion(uint8 version)
    {
        m_header.version = version;
    }

    void setCommand(uint8 command)
    {
        m_header.command = command;
    }

    void setAuthData(const RIPAuthentication& data)
    {
        m_authData = data;
    }

    void setAuthKey(string key)
    {
        m_authKey = key;
    }

    RIPHeader& getHeader() 
    { 
        return m_header; 
    }

    RipEntries& getEntries() 
    { 
        return m_entries; 
    }

    RIPAuthentication& getAuthData()
    {
        return m_authData;
    }

    string getAuthKey()
    {
        return m_authKey;
    }

    void loadFromPacket(const MemBlock* packet);

    void addRoute(IPV4Address net, IPV4Address mask, IPV4Address nhop, uint32 metric) 
    {
        RIPEntry entry;
        entry.routeTag = 0;
        entry.AFI = RIP_AFI_IP;
        entry.network = net;
        entry.subnetmask = mask;
        entry.nextHop = nhop;
        entry.metric = metric;

        m_entries.push_back(entry);
    }

    static bool testMd5Password(const RIPHeader* packet, uint32 packetSize, string password);

private:
    RIPHeader m_header;
    RipEntries m_entries;
    RIPAuthentication m_authData;
    string m_authKey;
};

#endif
