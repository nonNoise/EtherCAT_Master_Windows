#pragma once

#include <pcap.h>
#include <string.h>


#define EC_MAXLEN_ADAPTERNAME    128

typedef struct {        
	char name[EC_MAXLEN_ADAPTERNAME];		
	char description[EC_MAXLEN_ADAPTERNAME];
} pcapDeviceList_t;


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);


//================================================================================//
// デバイスリストの取得
//================================================================================//
int pcap_GetDeviceList(pcapDeviceList_t *dvicelist,int maxlist)
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];

	int device_num = 0;

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next)
	{
		if(device_num<maxlist)
		{
			//printf("%d. %s\n", device_num, d->name);
			strcpy_s(dvicelist[device_num].name, EC_MAXLEN_ADAPTERNAME, d->name);
			dvicelist[device_num].name[EC_MAXLEN_ADAPTERNAME-1] = '\n';
			if (d->description)
			{
				strcpy_s(dvicelist[device_num].description, EC_MAXLEN_ADAPTERNAME, d->name);
				dvicelist[device_num].description[EC_MAXLEN_ADAPTERNAME-1] = '\n';	
			}
			else
			{
				strcpy_s(dvicelist[device_num].description, EC_MAXLEN_ADAPTERNAME, "__________");
			}
			device_num++;
		}

	}
	/* Free the device list */
	pcap_freealldevs(alldevs);

	return device_num;
}

//===================================================================//
// デバイスオープン
//===================================================================//
pcap_t* pcap_OpenDevice(pcapDeviceList_t device)
{
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("Open: %s\n", device.name);

	/* Open the device */
	if ((adhandle = pcap_open_live(device.name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		printf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", device.name);
		return -1;
	}
	
	printf("\nlistening on %s...\n", device.description);
	return adhandle;
}
//===================================================================//
// デバイスクローズ
//===================================================================//

int pcap_CloseDevice(pcap_t* adhandle)
{
	pcap_close(adhandle);
}




void dump(const unsigned char* data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;
	for (i = 0; i < length; i++) {
		byte = data_buffer[i];
		printf(" %02x", data_buffer[i]);
		if ((i % 16 == 15) || (i == length - 1)) {
			for (j = 0; j < 15 - (i % 16); j++) {
				printf("   ");
			}
			printf("| ");
			for (j = (i - (i % 16)); j <= i; j++) {
				byte = data_buffer[j];
				if ((byte > 31) && (byte < 127))
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}
