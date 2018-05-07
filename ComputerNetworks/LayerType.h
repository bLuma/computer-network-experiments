#ifndef __LAYERTYPE_H
#define __LAYERTYPE_H

/*
  Layer type enum
*/
enum LayerType
{
    /// Ethernet
    LtEthernet,

    /// ARP - address resolution protocol
    LtARP,
    /// IPv4 - internet protocol v4
    LtIPv4,
    /// IPv6 - internet protocol v6
    LtIPv6,
    /// ICMP - internet control message protocol

    LtICMP,
    /// TCP - transmission control protocol
    LtTCP,
    /// UDP - user datagram protocol
    LtUDP,

    /// RIP - routing information protocol
    LtRIP
};

#endif
