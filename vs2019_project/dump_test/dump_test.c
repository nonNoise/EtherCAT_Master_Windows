#include <stdio.h>
#include <pcap.h>

#include "pcaplib.h"
#include "EtherCATlib.h"
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

    EtherCATFrame_t ecatf;
    ecatf.CMD = EtherCAT_Command_APWR;
    ecatf.IDX = 0x00;
    ecatf.ADP = 0x00;
    ecatf.ADO = 0x0120;
    ecatf.C = 0x00;
    ecatf.NEXT = 0x00;
    ecatf.IRQ = 0x00;
	ecatf.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    ecatf.DATA[0] = 0x02;
	ecatf.DATA[1] = 0x00;

    ecatf.DataSize = 2;
    ecatf.WKC = 0x00;
    
    Framebuff_t ecat_frame;
    Framebuff_t ecat_hedder;
    Framebuff_t soccet;
    Framebuff_t send;

     ethercat_fream(&ecatf,&ecat_frame);
     dump(ecat_frame.frame,ecat_frame.length);
     ethercat_hedder_add_frame(&ecat_frame,&ecat_hedder);
     dump(ecat_hedder.frame,ecat_hedder.length);
     socket_add_fream(&ecat_hedder,&soccet);
     dump(soccet.frame,soccet.length);

	u_char* Receive_packet = NULL;
	struct pcap_pkthdr* header = NULL;
	
	pcap_Fillter(&header, "ECAT");


	while(1)
	{


		pcap_RawSend(adhandle, soccet.frame , soccet.length);

		
		pcap_RawReceive(adhandle,Receive_packet,&header);

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

