#include "toolkit.h"
#include <sstream>
#include <iostream>
#include <iomanip>

static char DECHEX[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
inline void itoa16(uint8 byte, char* buffer)
{
    buffer[0] = DECHEX[byte / 16];
    buffer[1] = DECHEX[byte % 16];
    buffer[2] = '\0';
}

inline void itoa10(uint8 byte, char* buffer)
{
    if (!byte)
    {
        buffer[0] = '0';
        buffer[1] = '\0';
        return;
    }

    if (byte >= 100)
        *buffer++ = DECHEX[byte / 100];
    if (byte >= 10)
        *buffer++ = DECHEX[byte / 10 % 10];

    *buffer++ = DECHEX[byte % 10];
    *buffer = '\0';   
}

inline int atoi16(char c)
{
    for (uint32 i = 0; i < 16; i++)
        if (DECHEX[i] == c)
            return i;
    
    return -1;
}

string convertMacToStr(const MACAddress& address) 
{
    string str;
    char buf[3];

    for (int i = 0; i < ETH_MAC_LENGTH; i++) 
    {
        itoa16(address.bytes[i], buf);

        if (i)
            str += ":";

        str += buf;
    }

    return str;
}

string convertIPToStr(const IPV4Address& address)
{
    string str;
    char buf[4];
    buf[3] = '\0';

    for (int i = 0; i < sizeof(IPV4Address); i++)
    {
        itoa10(address.bytes[i], buf);

        if (i)
            str += ".";

        str += buf;
    }

    return str;
}

string convertIPToStr(const IPV6Address& address)
{
    string str;
    char buf[3];

    for (int i = 0; i < sizeof(IPV6Address); i++)
    {
        itoa16(address.bytes[i], buf);

        if (i)
            str += ":";

        str += buf;
    }

    return str;
}

IPV4Address convertStrToIP(string str)
{
    IPV4Address addr;
    stringstream ss(str);
    
    for (uint8 i = 0; i < IPV4_ADDR_LENGTH; i++)
    {
        uint32 byte;
        char dummy;

        ss >> byte;
        ss >> dummy;

        addr.bytes[i] = (uint8)byte;
    }

    return addr;
}

MACAddress convertStrToMac(string str)
{
    MACAddress addr;
    stringstream ss(str);
    
    for (uint8 i = 0; i < ETH_MAC_LENGTH; i++)
    {
        uint32 byte;
        char dummy;

        ss >> hex >> byte;
        ss >> dummy;

        addr.bytes[i] = (uint8)byte;
    }

    return addr;
}

string dumpData(const uint8* data, uint32 size)
{
    const uint8* temp = data;
    stringstream s;
    uint32 pos = 0;

    while (size > 0)
    {
        s.setf(ios::hex, ios::basefield);
        s.fill('0');

        s << "0x" << setw(4) << pos;

        uint32 cnt = size > 16 ? 16 : size;
        uint32 rem = 16 - cnt;
        
        temp = data;
        for (uint32 i = 0; i < cnt; i++)
        {
            s << " " << setw(2) << uint32(*temp);
            temp++;
        }

        for (uint32 i = 0; i < rem; i++)
        {
            s << "   ";
        }

        s << ' ';

        for (uint32 i = 0; i < cnt; i++)
        {
            s << (*data < ' ' ? '.' : (char)*data);
            data++;
        }

        s << endl;
        pos += cnt;

        size -= cnt;
    }

    return s.str();
}

string getDeviceInfo(pcap_if_t* device)
{
    stringstream ss;

    ss << "Device " << device->name << endl;
    ss << "Description: " << device->description << endl;

    pcap_addr_t* address = device->addresses;
    while (address)
    {
        if (address->addr && address->addr->sa_family == AF_INET)
        {
            #define CONVERT_ADDR_IF_YOU_CAN(addr) ((addr) && (addr)->sa_family == AF_INET ? IPV4Address( ((sockaddr_in*)(addr))->sin_addr.s_addr ) : IPV4Address())
        
            IPV4Address ipadd = CONVERT_ADDR_IF_YOU_CAN(address->addr);
            IPV4Address netmask = CONVERT_ADDR_IF_YOU_CAN(address->netmask);
            IPV4Address broadaddr = CONVERT_ADDR_IF_YOU_CAN(address->broadaddr);
            IPV4Address dstaddr = CONVERT_ADDR_IF_YOU_CAN(address->dstaddr);
        
            ss << "Address      " << convertIPToStr(ipadd) << endl << " netmask     " << convertIPToStr(netmask); 
            ss << endl << " broadcast   " << convertIPToStr(broadaddr) << endl << " destination " << convertIPToStr(dstaddr) << endl;
            #undef CONVERT_ADDR_IF_YOU_CAN
        } 
        else if (address->addr && address->addr->sa_family == AF_INET6)
        {
            #define CONVERT_ADDR_IF_YOU_CAN(addr) ((addr) && (addr)->sa_family == AF_INET6 ? IPV6Address( ((sockaddr_in6*)(addr))->sin6_addr.s6_addr ) : IPV6Address())
        
            IPV6Address ipadd = CONVERT_ADDR_IF_YOU_CAN(address->addr);
            IPV6Address netmask = CONVERT_ADDR_IF_YOU_CAN(address->netmask);
            IPV6Address broadaddr = CONVERT_ADDR_IF_YOU_CAN(address->broadaddr);
            IPV6Address dstaddr = CONVERT_ADDR_IF_YOU_CAN(address->dstaddr);
        
            ss << "Address      " << convertIPToStr(ipadd) << endl << " netmask     " << convertIPToStr(netmask); 
            ss << endl << " broadcast   " << convertIPToStr(broadaddr) << endl << " destination " << convertIPToStr(dstaddr) << endl;
            #undef CONVERT_ADDR_IF_YOU_CAN
        }

        address = address->next;
    }

    return ss.str();
}

string convertBinaryToHex(const uint8* ptr, uint32 size)
{
    stringstream ss;
    
    for (uint8 i = 0; i < size; i++)
    {
        ss.fill('0');
        ss.width(2);
        ss << hex << (uint32)ptr[i];
    }

    return ss.str();
}

void convertHexToBinary(uint8* ptr, string str)
{
    for (uint32 i = 0; i < str.length(); i += 2)
    {
        *ptr++ = atoi16(str[i]) * 16 + atoi16(str[i + 1]);
    }
}

uint32 getFirstBitsCount(uint32 value)
{
    uint32 bits = 0;

    while ((value & 0x80000000) && bits < 32)
    {
        value <<= 1;
        bits++;
    }

    return bits;
}

string listNetworkDevices(uint32* count, pcap_if_t* devices)
{
    pcap_if_t *alldevs = devices;
	pcap_if_t *d;
    int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
    stringstream ss;
	
    if (!devices)
    {
	    if(pcap_findalldevs(&alldevs, errbuf) == -1)
	    {
		    ss << "Error in pcap_findalldevs: " << errbuf;
		    return ss.str();
	    }
    }
	
	for(d=alldevs; d; d=d->next)
	{
        ss << ++i << ". " << d->name << " (" << (d->description ? d->description : "Bez popisu") << ")" << endl;
	}
	
    if (!devices)
        pcap_freealldevs(alldevs);

    if (count)
        *count = i;

    return ss.str();
}

string chooseNetworkDevice()
{
    pcap_if_t *alldevs;
	pcap_if_t *d;
    uint32 selected;
    uint32 num;
    char errbuf[PCAP_ERRBUF_SIZE];
    string deviceName;
    
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
	    return "";
    }

    cout << listNetworkDevices(&num, alldevs).c_str() << endl;
    do 
    {
        cout << "Choose a device (1 - " << num << "): ";
        cin >> selected;
    } while (selected < 1 || selected > num);
    
    selected--;

    for (d = alldevs; selected > 0; d = d->next, selected--);

    deviceName = d->name;

    pcap_freealldevs(alldevs);

    return deviceName;
}

bool attachFilter(const char* filter, pcap_t* handle, uint32 netmask)
{
    bpf_program fcode;

    if (pcap_compile(handle, &fcode, filter, 1, netmask) < 0)
        return false;
    
    if (pcap_setfilter(handle, &fcode) < 0)
        return false;

    return true;
}

pcap_t* openDevice(const char* deviceName)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    return pcap_open_live(deviceName,	// name of the device
				    	 65536,			// portion of the packet to capture. 
										// 65536 grants that the whole packet will be captured on all the MACs.
						 1,				// promiscuous mode (nonzero means promiscuous)
						 1000,			// read timeout
						 errbuf			// error buffer
						 );
}
