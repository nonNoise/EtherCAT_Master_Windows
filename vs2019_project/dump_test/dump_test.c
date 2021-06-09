#include <stdio.h>
#include <pcap.h>

#include "pcaplib.h"
#include "EtherCATlib.h"
#include "EtherCAT_API.h"

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);


void main()
{
	printf("HELLO\n");

	//pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];



	pcapDeviceList_t  dvicelist[10];
	int device_num = 0;

	device_num = pcap_GetDeviceList(dvicelist,10);

	for (int i = 0; i < device_num; i++)
	{
		printf("[%d]  %s :%s \n",i, dvicelist[i].description,dvicelist[i].name);

	}

	
	int select_device_num = 3;

	adhandle = pcap_OpenDevice(dvicelist[select_device_num]);

	//char* Filter = "ether broadcast";
	//char* Filter = "ether dst ff:ff:ff:ff:ff:ff";
	char* Filter = "ether src 03:01:01:01:01:01";

	pcap_Fillter(adhandle, Filter);


	/*
    EtherCATFrame_t ecatf;
    ecatf.CMD = EtherCAT_Command_APWR;
    ecatf.IDX = 0x00;
    ecatf.ADP = 0x00;
    ecatf.ADO = 0x0120;
    ecatf.C = 0x00;
    ecatf.NEXT = 0x00;
    ecatf.IRQ = 0x00;
	ecatf.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (5));
    ecatf.DATA[0] = 'H';
	ecatf.DATA[1] = 'E';
	ecatf.DATA[2] = 'L';
	ecatf.DATA[3] = 'L';
	ecatf.DATA[4] = 'O';
	ecatf.LEN = 5;
    ecatf.WKC = 0x00;
    */
	//EthereCAT_Reset(adhandle, 0x00);
	EtherCAT_EEPROM_Setup(adhandle,0x00);

	EtherCAT_SetUp(adhandle, 0x00);
	EtherCAT_GPIOMode(adhandle, 0x00, 0xFFFF);
	
	while (1)
	{
		EtherCAT_GPIO_Out(adhandle, 0x00, 0xFFFF);
		EtherCAT_GPIO_Out(adhandle, 0x00, 0x0000);

	}

	/*
	EtherCATFrame_t sendecat;
	EtherCATFrame_t readecat;
	uint32_t data = 0;

	sendecat.CMD = 0x0000;
	sendecat.ADO = 0x0000;
	sendecat.ADP = 0x0000;
	sendecat.IDX = 0x00;
	sendecat.ADP = 0x00;
	sendecat.C = 0x00;
	sendecat.NEXT = 0x00;
	sendecat.IRQ = 0x00;
	sendecat.WKC = 0x00;
	sendecat.DATA = NULL;
	sendecat.LEN = 0;

	data = 0x0000;
	sendecat.CMD = EtherCAT_Command_APRD;
	sendecat.ADO = 0x0E08;
	sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (4));
	sendecat.DATA[0] = data & 0xFF;
	sendecat.DATA[1] = (data >> 8) & 0xFF;
	sendecat.DATA[2] = (data >> 16) & 0xFF;
	sendecat.DATA[3] = (data >> 24) & 0xFF;
	sendecat.LEN = 4;

	EthereCAT_SendRead(adhandle, &sendecat, &readecat);
	*/


	 char* Receive_packet;
	 struct pcap_pkthdr* header;
	

	//while(1)
	//{
		
		/*
		if(pcap_RawReceive(adhandle,&header,&Receive_packet)>0)
		{
			struct tm* ltime;
			char timestr[16];
			time_t local_tv_sec;

			local_tv_sec = header->ts.tv_sec;
			ltime = localtime(&local_tv_sec);
			strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
			printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

			Framebuff_t rdata;
			EtherCATFrame_t getframe;
			rdata.frame = Receive_packet;
			rdata.length = header->len;

			dump(rdata.frame, rdata.length);
			
			ethercat_decode_fream(&rdata,&getframe);

			printf("--------------------------------------------------------------------\n");

			printf("CMD= 0x%02X \n", getframe.CMD);
			printf("IDX= 0x%02X \n", getframe.IDX);
			printf("ADP= 0x%02X \n", getframe.ADP);
			printf("ADO= 0x%02X \n", getframe.ADO);
			printf("LEN= 0x%02X \n", getframe.LEN);
			printf("IRQ= 0x%02X \n", getframe.IRQ);
			for (int i = 0; i < getframe.LEN; i++)
			{
				printf("DATA[%d]: 0x%02X  %c\n", i, getframe.DATA[i], getframe.DATA[i]);

			}
			printf("WKC= 0x%02X \n", getframe.WKC);
		}
		*/

	//}
	//return 0;

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

