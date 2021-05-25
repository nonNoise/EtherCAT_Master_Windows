#pragma once

#include <pcap.h>
#include <string.h>

//================================================================================//
// デバイスリストの取得
//================================================================================//
int pcap_getDeviceList(char dvicelist[10][100])
{

	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];

	int device_num = 0;
	//char dvicelist[10][100];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next)
	{
		//printf("%d. %s", device_num++, d->name);
		strcpy_s(dvicelist[device_num++], 100, d->name);
		if (d->description)
		{
			//printf(" (%s)\n", d->description);
		}
		else
		{
			//printf(" (No description available)\n");
		}
	}
	return device_num;
}
