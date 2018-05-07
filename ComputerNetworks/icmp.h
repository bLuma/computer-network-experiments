#ifndef __ICMP_H
#define __ICMP_H

#include "types.h"

#define ICMP_HEADER_LENGTH (1+1+2)

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_TYPE_SOURCE_QUENCH 4
#define ICMP_TYPE_REDIRECT_MESSAGE 5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_ROUTER_ADVERTISEMENT 9
#define ICMP_TYPE_ROUTER_SOLICITATION 10
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_BAC_IP_HEADER 12
#define ICMP_TYPE_TIMESTAMP 13
#define ICMP_TYPE_TIMESTAMP_REPLY 14
#define ICMP_TYPE_INFORMATION_REQUEST 15
#define ICMP_TYPE_INFORMATION_REPLY 16
#define ICMP_TYPE_ADDRESS_MASK_REQUEST 17
#define ICMP_TYPE_ADDRESS_MASK_REPLY 18

struct CN_DLLSPEC ICMPHeader {
    uint8 type;
    uint8 code;
    uint16 checksum;
    //uint16 id;
    //uint16 sequence;

    string toString() const {
        switch (type)
        {
        case ICMP_TYPE_ECHO_REPLY: 
            return "Echo reply";
        case ICMP_TYPE_DESTINATION_UNREACHABLE: 
            return "Destination unreachable";
        case ICMP_TYPE_SOURCE_QUENCH: 
            return "Source quench";
        case ICMP_TYPE_REDIRECT_MESSAGE:
            return "Redirect message";
        case ICMP_TYPE_ECHO_REQUEST:
            return "Echo request";
        case ICMP_TYPE_ROUTER_ADVERTISEMENT:
            return "Router advertisement";
        case ICMP_TYPE_ROUTER_SOLICITATION:
            return "Router solicitation";
        case ICMP_TYPE_TIME_EXCEEDED:
            return "Time exceeded";
        case ICMP_TYPE_BAC_IP_HEADER:
            return "Bad IP header";
        case ICMP_TYPE_TIMESTAMP:
            return "Timestamp";
        case ICMP_TYPE_TIMESTAMP_REPLY:
            return "Timestamp reply";
        case ICMP_TYPE_INFORMATION_REQUEST:
            return "Information request";
        case ICMP_TYPE_INFORMATION_REPLY:
            return "Information reply";
        case ICMP_TYPE_ADDRESS_MASK_REQUEST:
            return "Address mask request";
        case ICMP_TYPE_ADDRESS_MASK_REPLY:
            return "Address mask reply";
        }

        return "<unk>";
    }

    uint16 calculateChecksum(uint8* data = NULL, uint32 dataLen = 0) const {
        ICMPHeader copy = *this;
        copy.checksum = 0;

        uint32 value = 0;

        uint16* ptr = (uint16*)&copy;
        for (int i = 0; i < ICMP_HEADER_LENGTH; i += 2)
        {
            value += (*ptr);

            ptr++;
        }

        if (dataLen)
        {
            ptr = (uint16*)data;
            for (uint32 i = 0; i < dataLen; i += 2)
            {
                value += (*ptr);

                ptr++;
            }
        }

        while (value >> 16) 
        {
            value = (value & 0xFFFF) + (value >> 16);
        }

        value = ~value;

        return (uint16(value & 0xFFFF));
    }
};

#endif
