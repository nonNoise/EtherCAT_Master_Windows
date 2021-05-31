#pragma once

#include <pcap.h>
#include <string.h>


#define EC_MAXLEN_ADAPTERNAME    128

typedef struct {        
	char name[EC_MAXLEN_ADAPTERNAME];		
	char description[EC_MAXLEN_ADAPTERNAME];
} pcapDeviceList_t;


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void dump(const unsigned char* data_buffer, const unsigned int length);


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
				strcpy_s(dvicelist[device_num].description, EC_MAXLEN_ADAPTERNAME, d->description);
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



int pcap_RawSend(pcap_t* adhandle,const u_char *send_packet,int length)
{
	if (pcap_sendpacket(adhandle, send_packet, length) != 0)
	{
		printf(stderr, "\nError sending the packet: \n", pcap_geterr(adhandle));
	}
}

int pcap_RawReceive(pcap_t* adhandle,const u_char* Receive_packet,struct pcap_pkthdr* header)
{
	int res;
	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;

	if(res = pcap_next_ex(adhandle, &header, &Receive_packet) != 0)
	{
		/* convert the timestamp to readable format */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

		//printf("packet size = %d\n", header.len);
		dump(Receive_packet, header->len);
	}
}

int pcap_Fillter(struct pcap_pkthdr* header,char filter_exp[])
{
	/*
	struct bpf_program fp;
	bpf_u_int32 net=0;		//IPアドレス 
	// フィルタをコンパイルして適用する 
	if (pcap_compile(header, &fp, filter_exp, 0, net) == -1) {
		printf("フィルタ「%s」を解析できませんでした: %s\n", filter_exp, pcap_geterr(header));
		exit(1);
	}
	if (pcap_setfilter(header, &fp) == -1) {
		printf("フィルタ「%s」の組み込みができませんでした: %s\n", filter_exp, pcap_geterr(header));
		exit(1);
	}
	*/
}