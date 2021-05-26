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
		printf("[%d]  %s\n",i, dvicelist[i].name);

	}

	
	int select_device_num = 4;

	adhandle = pcap_OpenDevice(dvicelist[select_device_num]);
	
	struct pcap_pkthdr* header;
	const u_char* packet;
	const u_char* pkt_data;

	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;
	int res;

	res = pcap_next_ex(adhandle, &header, &pkt_data);
	
	if (res == 0)
	{
		/* Timeout elapsed */
		//continue;
	}
			
	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
	//printf("packet size = %d\n", header.len);
	dump(pkt_data, header->len);

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

