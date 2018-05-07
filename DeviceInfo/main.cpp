#include <toolkit.h>

void main(int argc, char** argv)
{
    pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	for(d=alldevs; d; d=d->next)
	{
        ++i;
		printf("%s\n", getDeviceInfo(d).c_str());
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}

	pcap_freealldevs(alldevs);
}
