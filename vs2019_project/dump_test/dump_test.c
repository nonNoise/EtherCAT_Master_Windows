#include <stdio.h>
#include <pcap.h>

#include "pcaplib.h"

void main()
{
	printf("HELLO\n");

	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];


	char  dvicelist[10][100];
	int device_num = 0;

	device_num = pcap_getDeviceList(dvicelist);

	for (int i = 0; i < device_num; i++)
	{
		printf("[%d]  %s\n",i, dvicelist[i]);

	}

	int select_device_num = 4;

	printf("[%d]. %s", select_device_num, dvicelist[select_device_num]);

	/* Open the device */
	if ((adhandle = pcap_open_live(dvicelist[select_device_num],	// name of the device
									65536,			// portion of the packet to capture. 
													// 65536 grants that the whole packet will be captured on all the MACs.
									1,				// promiscuous mode (nonzero means promiscuous)
									1000,			// read timeout
									errbuf			// error buffer
					)) == NULL)
	{
		//fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		return -1;
	}

}


