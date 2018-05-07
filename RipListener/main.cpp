#include <types.h>
#include <pcap.h>
#include <iostream>
#include <toolkit.h>
#include <tcpip.h>
#include <rip.h>
#include <RipConstructor.h>
#include <KeyManager.h>
#include <PasswordBreaker.h>
#include <ThreadedPasswordBreaker.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void handleRipPacket(const RIPHeader* ripheader, uint32 ripLen);

KeyManager keyManager;

void main()
{
	pcap_t *adhandle;
	
	string deviceName = chooseNetworkDevice();
	
    if (!(adhandle = openDevice(deviceName.c_str())))
    {
        cerr << "Cant open device " << deviceName.c_str() << endl;
        return;
    }

    if (!attachFilter("ip and udp and dst port 520", adhandle))
    {
        cerr << "Cant set filter" << endl;
        return;
    }

    cout << "Listening on " << deviceName.c_str() << "..." << endl;

	pcap_loop(adhandle, 0, packet_handler, (u_char*)adhandle);
	
	pcap_close(adhandle);
}

class PasswordCallback : public ICallback
{
public:
    void call(void* data)
    {
        ThreadedPasswordBreaker* breaker = (ThreadedPasswordBreaker*)data;

        cout << "Key found: ";
        char hash[MD5_DIGEST_LENGTH + 1];
        memcpy(hash, (uint8*)breaker->getData() + breaker->getDataSize() - MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH);
        hash[MD5_DIGEST_LENGTH] = 0;

        RIPHeader* ripheader = (RIPHeader*)breaker->getData();
        RIPAuthenticationMD5* ripauth = (RIPAuthenticationMD5*)(ripheader + 1);
        
        keyManager.assign(ripauth->keyId, hash);

        cout << hash << endl;

        delete[] breaker->getData();
        delete[] breaker->getHash();
        delete breaker;
        delete this;
    }
};

void handleRipPacket(const RIPHeader* ripheader, uint32 ripLen)
{
    Rip packet;
    MemBlock mb((uint8*)ripheader, ripLen, false);
    packet.loadFromPacket(&mb);

    RIPHeader& goodRipHeader = packet.getHeader();
    RIPAuthentication& goodRipAuth = packet.getAuthData();

    cout << "RIP version " << (int)goodRipHeader.version << " command " << (int)goodRipHeader.command << endl;
    if (goodRipHeader.mustBeZero)
        cout << "  routing domain (nebo nula): " << goodRipHeader.mustBeZero << endl;

    RipEntries entries = packet.getEntries();
    for (RipEntries::iterator it = entries.begin(); it != entries.end(); it++)
    {
        RIPEntry entry = *it;

        cout << "network: " << convertIPToStr(entry.network) << "/" << getFirstBitsCount(convertNtoH(entry.subnetmask.address)) <<
            " metric: " << entry.metric << endl;
        if (entry.nextHop.address || entry.routeTag)
            cout << "  next hop: " << convertIPToStr(entry.nextHop) << " route tag: " << entry.routeTag << endl;
    }

    if (goodRipAuth.AFI)
    {
        switch (goodRipAuth.AuType)
        {
        case RIP_AUTHENTICATION_TYPE_PASSWORD:
            cout << "plain text authentication: " << goodRipAuth.getKeyData().c_str() << endl;
            break;

        case RIP_AUTHENTICATION_TYPE_MD5:
            RIPAuthenticationMD5* authdata = (RIPAuthenticationMD5*)&goodRipAuth;
            cout << "md5 authentication " << endl;
            cout << "  key id " << (int)authdata->keyId << " seq " << authdata->sequenceNumber << endl;
            cout << "  hash " << packet.getAuthKey().c_str() << endl;

            if (packet.getAuthKey().length() > 0)
            {
                uint32 ripSize = RIP_LENGTH(&packet);

                if (keyManager.hasKey(authdata->keyId) && 
                    Rip::testMd5Password(ripheader, ripSize, keyManager.getKey(authdata->keyId)))
                {
                    cout << "Key already found before: " << keyManager.getKey(authdata->keyId).c_str() << endl;
                }
                else
                {
                    /*char hash[MD5_DIGEST_LENGTH + 1];
                    convertHexToBinary((uint8*)hash, packet.getAuthKey());

                    ThreadedPasswordBreaker pwdBreaker;
                    pwdBreaker.setData((uint8*)ripheader, ripSize);
                    pwdBreaker.setKey((uint8*)ripheader + ripSize - MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH);
                    pwdBreaker.setHash((uint8*)hash, MD5_DIGEST_LENGTH);
                    pwdBreaker.crack();

                    cout << "Klic prolomen: ";
                    memcpy(hash, (uint8*)ripheader + ripSize - MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH);
                    hash[MD5_DIGEST_LENGTH] = 0;

                    cout << hash << endl;

                    keyManager.assign(authdata->keyId, hash);*/

                    char* hash = new char[MD5_DIGEST_LENGTH + 1];
                    uint8* ripdata = new uint8[ripSize];
                    memcpy(ripdata, ripheader, ripSize);

                    convertHexToBinary((uint8*)hash, packet.getAuthKey());

                    ThreadedPasswordBreaker* pwdBreaker = new ThreadedPasswordBreaker;
                    pwdBreaker->setData((uint8*)ripdata, ripSize);
                    pwdBreaker->setKey((uint8*)ripdata + ripSize - MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH);
                    pwdBreaker->setHash((uint8*)hash, MD5_DIGEST_LENGTH);
                    
                    pwdBreaker->setCallback(new PasswordCallback());

                    pwdBreaker->crack();

                    /*cout << "Klic prolomen: ";
                    memcpy(hash, (uint8*)ripdata + ripSize - MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH);
                    hash[MD5_DIGEST_LENGTH] = 0;

                    cout << hash << endl;

                    keyManager.assign(authdata->keyId, hash);*/
                }
            }
            break;
        }
    }
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    
    const EthernetFrame* frame = (EthernetFrame*)pkt_data;

    printf("source mac:  %s \n", convertMacToStr(frame->source).c_str());

    if (convertNtoH(frame->lenOrType) == ETH_TYPE_IPV4)
    {
        const IPV4Header* ipheader = (const IPV4Header*)(pkt_data + ETHERNET_HEADER_LENGTH);

        printf("source ip: %s \n", convertIPToStr(ipheader->source).c_str());

        if (ipheader->protocol == IP_PROTOCOL_UDP)
        {
            const UDPHeader* udpheader = (const UDPHeader*)((const char*)ipheader + IPV4_HEADER_LENGTH(ipheader));

            if (convertNtoH(udpheader->destinationPort) == RIP_UDP_PORT)
            {
                const RIPHeader* ripheader = (const RIPHeader*)((const char*)udpheader + UDP_HEADER_LENGTH);

                handleRipPacket(ripheader, convertNtoH(udpheader->length) - UDP_HEADER_LENGTH);
            }
        }
    }

    // printf("\n\n%s\n\n", dumpData(pkt_data, header->len).c_str());
}
