#ifndef __TOOLKIT_H
#define __TOOLKIT_H

#include "types.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include <pcap.h>

/// Converts MAC address to string
CN_DLLSPEC string convertMacToStr(const MACAddress& address);
/// Converts IPv4 address to string
CN_DLLSPEC string convertIPToStr(const IPV4Address& address);
/// Converts IPv6 address to string
CN_DLLSPEC string convertIPToStr(const IPV6Address& address);

/// Converts string to IPv4 address
/// format: xxx.xxx.xxx.xxx
CN_DLLSPEC IPV4Address convertStrToIP(string str);
/// Converts string to MAC
/// format: xx:xx:xx:xx:xx:xx
/// accepts hexadecimal numbers
CN_DLLSPEC MACAddress convertStrToMac(string str);

/// Converts data to readable ascii dump
/// hex and dec output
CN_DLLSPEC string dumpData(const uint8* data, uint32 size);

/// Gets information about device
CN_DLLSPEC string getDeviceInfo(pcap_if_t* device);

/// Converts binary data to hex string
CN_DLLSPEC string convertBinaryToHex(const uint8* ptr, uint32 size);

/// Converts hex string to binary data
CN_DLLSPEC void convertHexToBinary(uint8* ptr, string str);

/// Counts number of 1bits from number prefix
CN_DLLSPEC uint32 getFirstBitsCount(uint32 value);

/// Returns brief description of network devices
CN_DLLSPEC string listNetworkDevices(uint32* count = NULL, pcap_if_t* devices = NULL);

/// Prompts user to console to choose net device
CN_DLLSPEC string chooseNetworkDevice();

/// Attaches filter to open net device
CN_DLLSPEC bool attachFilter(const char* filter, pcap_t* handle, uint32 netmask = 0);

/// Opens device in promiscuous mode
CN_DLLSPEC pcap_t* openDevice(const char* deviceName);

/// Macro for conversion of string to MAC
#define MACc(x) (convertStrToMac(x))
/// Macro for conversion of string to IPv4
#define IPv4c(x) (convertStrToIP(x))

#endif
