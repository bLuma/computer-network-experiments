
#include "types.h"

#include "toolkit.h"
#include "endian.h"
#include "tcpip.h"

#include <iostream>
#include <pcap.h>
#include <Windows.h>

#include "EthernetConstructor.h"
#include "ArpConstructor.h"
#include "IPv4Constructor.h"
#include "UdpConstructor.h"
#include "RipConstructor.h"
#include "LayerStack.h"
#include "ArpCache.h"
#include "DataLayer.h"

using namespace std;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//ArpCache arpcache;

DWORD WINAPI sendRoutine(void* param)
{
    Sleep(1500);
    printf("SENDING #####################################\n");

    EthernetConstructor* ec = new EthernetConstructor;
    ArpConstructor* ac = new ArpConstructor;
    //IPv4Constructor* ic = new IPv4Constructor;
    //UdpConstructor* uc = new UdpConstructor;
   // RipConstructor* rc = new RipConstructor;
    //DataLayer* dl = new DataLayer;


    LayerStack stack;

    stack.setLayer(2, ec);
    stack.setLayer(3, ac);
   // stack.setLayer(3, ic);
    //stack.setLayer(4, uc);
    //stack.setLayer(7, dl);
    //stack.setLayer(5, rc);

    // 00-1f-c6-58-a9-76 nas router
    // 00:1b:fc:57:ac:14 sec router

    ac->setReply();
    ac->setSourceHwAddr(MACc("10:20:30:40:50:60"));
    ac->setSourceProtoAddr(IPv4c("192.168.1.200"));
    ac->setDestinationHwAddr(MACc("00:1e:8c:0f:e6:8c"));
    ac->setDestinationProtoAddr(IPv4c("192.168.1.2"));

    //ec->setSourceAddr(MACc("00-1f-c6-58-a9-76"));
    //ec->setDestinationAddr(MACc("00-1E-8C-0F-E6-8C"));
    //ec->setDestinationAddr(MACc("ff-ff-ff-cd-cd-cd"));

    //ic->setUpperProtocol(0);
    //ic->setDestinationAddr(IPv4c("192.168.1.2"));
    //ic->setSourceAddr(IPv4c("192.168.56.1"));
    //ic->setTTL(1);

    //uc->setSourcePort(20150);
    //uc->setDestinationPort(20151);
    //uc->setChecksumCalculation(true);

    //ic->setUpperProtocol(IP_PROTOCOL_ICMP);

    /*MemBlock* mm = new MemBlock(ICMP_HEADER_LENGTH + 4);
    ICMPHeader* icmp = (ICMPHeader*)mm->getPtr();
    icmp->type = ICMP_TYPE_ECHO_REQUEST;
    icmp->code = 0;*/

   /* Rip rip;
    rip.setVersion(2);
    rip.setCommand(RIP_COMMAND_REPLY);

    rip.addRoute(
        IPv4c("192.168.120.0"),
        IPv4c("255.255.255.0"),
        IPv4c("0.0.0.0"),
        5);

    RIPAuthenticationMD5 md5;
    md5.sequenceNumber = 1;
    md5.authDataLen = 20;
    md5.keyId = 1;

    rip.setAuthData(*(RIPAuthentication*)&md5);
    rip.setAuthKey("heslo");

    rc->setData(&rip);*/

    /*IPV4Address* addr = (IPV4Address*)&mm->getPtr()[4];
    *addr = IPv4c("192.168.1.200");

    IPV4Header* iphead = (IPV4Header*)&mm->getPtr()[4 + 4];
    iphead->ttl = 5;
    iphead->setVersion(4);
    iphead->setHeaderLength(20);
    iphead->source = IPv4c("192.168.1.2");
    iphead->destination = IPv4c("192.168.2.2");
    iphead->length = convertHtoNs(UINT16M(20));
    iphead->protocol = IP_PROTOCOL_TCP;

    iphead->checksum = iphead->calculateChecksum();*/

    /*icmp->checksum = icmp->calculateChecksum(NULL, 0);//(uint8*)addr, 4+20);

    dl->setData(mm);*/

    MemBlock* mem = stack.construct();
    pcap_sendpacket((pcap_t*)param, mem->getPtr(), mem->getSize());

    delete mem;
    delete ec;
    delete ac;
    //delete ic;
    //delete uc;
   // delete rc;
    //delete dl;
    //delete mm;

    return 0;
}

DWORD WINAPI sendRoutineB(void* param)
{
    Sleep(1500);
    printf("SENDING #####################################\n");

    EthernetConstructor* ec = new EthernetConstructor;
    IPv4Constructor* ic = new IPv4Constructor;
    DataLayer* dl = new DataLayer;

    LayerStack stack;

    stack.setLayer(2, ec);
    stack.setLayer(3, ic);
    stack.setLayer(4, dl);

    // 00-1f-c6-58-a9-76 nas router
    // 00:1b:fc:57:ac:14 sec router
    ec->setSourceAddr(MACc("00:1b:fc:57:ac:16"));
    ec->setDestinationAddr(MACc("00:1b:fc:57:ac:14"));

    ic->setUpperProtocol(IP_PROTOCOL_TCP);
    ic->setDestinationAddr(IPv4c("10.0.0.139"));
    ic->setSourceAddr(IPv4c("10.0.0.141"));
    ic->setTTL(128);

    IPV4Header ipv4header;
    ipv4header.destination = IPv4c("10.0.0.139");
    ipv4header.source = IPv4c("10.0.0.141");

    TCPHeader header;
    memset(&header, 0, sizeof(TCPHeader));

    header.destinationPort = 80;
    header.sourcePort = 8001;
    header.windowSize = 8192;
    header.setDataOffset(20);

    convertHN(header.destinationPort);
    convertHN(header.sourcePort);
    convertHN(header.windowSize);

    header.setFlag(Syn);

    header.checksum = header.calculateChecksum(ipv4header, NULL);

    
    for (int i = 0; i < 100000; i++)
    {
        header.sourcePort = rand() % 65000;
        header.sequenceNum = rand() % 2000000;

        header.checksum = header.calculateChecksum(ipv4header, NULL);

        MemBlock* memblock = new MemBlock(TCP_HEADER_LENGTH(&header));
        memcpy(memblock->getPtr(), &header, TCP_HEADER_LENGTH(&header));

        dl->setData(memblock);

        MemBlock* mem = stack.construct();

        pcap_sendpacket((pcap_t*)param, mem->getPtr(), mem->getSize());
        Sleep(50);

        delete memblock;
        delete mem;
        break;
    }

    //delete mem;
    delete ec;
    delete ic;
    delete dl;

    return 0;
}

void sendAck(void* param, uint32 seq, uint32 ack, uint32 srcport)
{
    EthernetConstructor* ec = new EthernetConstructor;
    IPv4Constructor* ic = new IPv4Constructor;
    DataLayer* dl = new DataLayer;

    LayerStack stack;

    stack.setLayer(2, ec);
    stack.setLayer(3, ic);
    stack.setLayer(4, dl);

    // 00-1f-c6-58-a9-76 nas router
    // 00:1b:fc:57:ac:14 sec router
    ec->setSourceAddr(MACc("00:1b:fc:57:ac:15"));
    ec->setDestinationAddr(MACc("00:1b:fc:57:ac:14"));

    ic->setUpperProtocol(IP_PROTOCOL_TCP);
    ic->setDestinationAddr(IPv4c("10.0.0.139"));
    ic->setSourceAddr(IPv4c("10.0.0.141"));
    ic->setTTL(128);

    IPV4Header ipv4header;
    ipv4header.destination = IPv4c("10.0.0.139");
    ipv4header.source = IPv4c("10.0.0.141");

    TCPHeader header;
    memset(&header, 0, sizeof(TCPHeader));

    header.destinationPort = 80;
    header.sourcePort = srcport;
    header.windowSize = 5840;
    header.setDataOffset(20);
    header.ackNum = seq + 1;
    header.sequenceNum = ack;

    convertHN(header.destinationPort);
    convertHN(header.sourcePort);
    convertHN(header.windowSize);
    convertHN(header.sequenceNum);
    convertHN(header.ackNum);

    header.setFlag(Ack);

    header.checksum = header.calculateChecksum(ipv4header, NULL);

    MemBlock* memblock = new MemBlock(TCP_HEADER_LENGTH(&header));
    memcpy(memblock->getPtr(), &header, TCP_HEADER_LENGTH(&header));

    dl->setData(memblock);

    MemBlock* mem = stack.construct();

    pcap_sendpacket((pcap_t*)param, mem->getPtr(), mem->getSize());

    delete mem;
    delete ec;
    delete ic;
    delete dl;
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");

        cout << getDeviceInfo(d).c_str() << endl;
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

    //CreateThread(NULL, 0, sendRoutine, adhandle, 0, NULL);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, (u_char*)adhandle);
	
	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    
    const EthernetFrame* frame = (EthernetFrame*)pkt_data;
    printf("  dest: %s \n", convertMacToStr(frame->destination).c_str());
    printf("  src:  %s \n", convertMacToStr(frame->source).c_str());
    printf("  type: 0x%X \n", convertNtoH(frame->lenOrType));

    if (convertNtoH(frame->lenOrType) == ETH_TYPE_IPV4)
    {
        const IPV4Header* ipheader = (const IPV4Header*)(pkt_data + ETHERNET_HEADER_LENGTH);

        printf("    ver: %u \n", ipheader->getVersion());
        printf("    dest ip:   %s \n", convertIPToStr(ipheader->destination).c_str());
        printf("    source ip: %s \n", convertIPToStr(ipheader->source).c_str());

        printf("    checksum: %x | %x \n", ipheader->checksum, ipheader->calculateChecksum());

        //arpcache.add(ipheader->source, frame->source);
        //arpcache.print(cout);

        if (ipheader->protocol == IP_PROTOCOL_TCP)
        {
            const TCPHeader* tcpheader = (const TCPHeader*)((const char*)ipheader + IPV4_HEADER_LENGTH(ipheader));

            MemBlock* userData = NULL;

            uint32 ipdatalen = convertNtoH(ipheader->length) - ipheader->getHeaderLength();
            uint32 tcpdatalen = ipdatalen - TCP_HEADER_LENGTH(tcpheader);

            if (tcpdatalen)
            {
                uint8* data = (uint8*)tcpheader + TCP_HEADER_LENGTH(tcpheader);

                userData = new MemBlock(tcpdatalen);
                memcpy(userData->getPtr(), data, tcpdatalen);
            }

            printf("      tcp \n");
            printf("      dest port:   %u \n", convertNtoH(tcpheader->destinationPort));
            printf("      source port: %u \n", convertNtoH(tcpheader->sourcePort));
            cout << "      flags: " << tcpheader->getFlags() << endl;
            cout << "      checksum: " << hex << tcpheader->checksum  << " | " << hex << tcpheader->calculateChecksum(*ipheader, userData) << endl;

            if (userData)
                delete userData;

            //if (tcpheader->hasFlag(Syn) && tcpheader->hasFlag(Ack))
            //    sendAck(param, convertNtoH(tcpheader->sequenceNum), convertNtoH(tcpheader->ackNum), convertNtoH(tcpheader->destinationPort));
        }
        else if (ipheader->protocol == IP_PROTOCOL_UDP)
        {
            const UDPHeader* udpheader = (const UDPHeader*)((const char*)ipheader + IPV4_HEADER_LENGTH(ipheader));

            printf("      udp \n");
            printf("      dest port:   %u \n", convertNtoH(udpheader->destinationPort));
            printf("      source port: %u \n", convertNtoH(udpheader->sourcePort));

            if (convertNtoH(udpheader->destinationPort) == RIP_UDP_PORT)
            {
                const RIPHeader* ripheader = (const RIPHeader*)((const char*)udpheader + UDP_HEADER_LENGTH);

                Rip packet;
                MemBlock mb((uint8*)ripheader, convertNtoH(udpheader->length) - UDP_HEADER_LENGTH, false);
                packet.loadFromPacket(&mb);

                cout << "RIP version " << (int)packet.getHeader().version << " command " << (int)packet.getHeader().command << endl;

                RipEntries entries = packet.getEntries();
                for (RipEntries::iterator it = entries.begin(); it != entries.end(); it++)
                {
                    RIPEntry entry = *it;

                    cout << "network: " << convertIPToStr(entry.network) << " mask: " << convertIPToStr(entry.subnetmask) << 
                        " metric: " << entry.metric;
                }
            }

        }
        else if (ipheader->protocol == IP_PROTOCOL_ICMP)
        {
            const ICMPHeader* icmpheader = (const ICMPHeader*)((const char*)ipheader + IPV4_HEADER_LENGTH(ipheader));

            printf("      icmp - %s \n", icmpheader->toString().c_str());
            printf("      type: %u \n", icmpheader->type);
            printf("      code: %u \n", icmpheader->code);

        }
    }
    else if (convertNtoH(frame->lenOrType) == ETH_TYPE_IPV6)
    {
        const IPV6Header* ipheader = (const IPV6Header*)(pkt_data + ETHERNET_HEADER_LENGTH);

        printf("    ver: %u \n", ipheader->getVersion());
        printf("    dest ip:   %s \n", convertIPToStr(ipheader->destination).c_str());
        printf("    source ip: %s \n", convertIPToStr(ipheader->source).c_str());
    }
    else if (convertNtoH(frame->lenOrType) == ETH_TYPE_ARP)
    {
        const ARPHeader* arpheader = (const ARPHeader*)((const char*)pkt_data + ETHERNET_HEADER_LENGTH);

        printf("    arp - %s \n", convertNtoH(arpheader->operation) == 1 ? "request" : "reply");

        if (convertNtoH(arpheader->hwType) == ARP_HW_TYPE_ETHERNET &&
            convertNtoH(arpheader->protocolType) == ARP_PROTOCOL_IPV4)
        {
            const ARPEthernetIPV4* arpextended = (const ARPEthernetIPV4*)((const char*)arpheader + ARP_HEADER_LENGTH);
            
            printf("    src hw:    %s \n", convertMacToStr(arpextended->sourceHwAddr).c_str());
            printf("    source ip: %s \n", convertIPToStr(arpextended->sourceProtocolAddr).c_str());
            printf("    dest hw:   %s \n", convertMacToStr(arpextended->targetHwAddr).c_str());
            printf("    dest ip:   %s \n", convertIPToStr(arpextended->targetProtocolAddr).c_str());
        }

    }
    printf("\n");

    // printf("%s\n", dumpData(pkt_data, header->len).c_str());
}
