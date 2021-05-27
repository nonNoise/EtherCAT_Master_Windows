#include <stdio.h>
#include <pcap.h>

#include "pcaplib.h"

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);


void main()
{
	printf("HELLO\n");

	//pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];


	pcapDeviceList_t  dvicelist[10];
	int device_num = 0;

	device_num = pcap_GetDeviceList(dvicelist,10);

	for (int i = 0; i < device_num; i++)
	{
		printf("[%d]  %s :%s \n",i, dvicelist[i].description,dvicelist[i].name);

	}

	
	int select_device_num = 4;

	adhandle = pcap_OpenDevice(dvicelist[select_device_num]);



	unsigned char send_packet[42] = {
	0x11,0x22,0x33,0x44,0x55,0x66,0x12,0x34,0x56,0x78,0x9a,0xbc,0x08,0x06,
	0,1,8,0,6,4,0,2,12,34,56,78,0x9a,0xbc,192,168,0,2,
	11,22,33,44,55,66,192,168,0,1
	};

	u_char* Receive_packet = NULL;
	struct pcap_pkthdr* header = NULL;
	//pcap_t* adhandle;

	while(1)
	{
		pcap_RawSend(send_packet,100,adhandle);

		pcap_RawReceive(Receive_packet,header,adhandle);

	}


	return 0;
}



/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

}

