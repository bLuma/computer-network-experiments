#include <toolkit.h>
#include <ArgParser.h>
#include <pcap.h>
#include <iostream>
#include <tcpip.h>
#include "PacketParser.h"

PacketParser parser;

bool parseInformation = true;
bool outDumpData = false;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char** argv)
{
    ArgParser arguments;
    arguments.addArgument("filter", "Sets pcap filter");
    arguments.addArgument("noinfo", "No information output", "", false, true);
    arguments.addArgument("dump", "Dumps full packet", "", false, true);
    
    if (!arguments.parseArguments(argc, argv))
        return 0;

    string device = chooseNetworkDevice();
    pcap_t* handle = openDevice(device.c_str());

    string filter = arguments.getString("filter");
    if (!filter.empty())
    {
        if (!attachFilter(filter.c_str(), handle))
        {
            cerr << "Cant attach filter" << endl;
            return 1;
        }
    }

    if (arguments.isTrue("noinfo"))
        parseInformation = false;
    if (arguments.isTrue("dump"))
        outDumpData = true;

    pcap_loop(handle, 0, packet_handler, NULL);
	
	pcap_close(handle);

    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    if (parseInformation)
    {
        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;

        /* convert the timestamp to readable format */   
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

        parser.parse(pkt_data, header->caplen);
        cout << endl;
    }

    if (outDumpData)
        printf("%s\n", dumpData(pkt_data, header->len).c_str());
}
