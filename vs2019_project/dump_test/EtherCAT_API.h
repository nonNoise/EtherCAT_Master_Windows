#include <stdio.h>
#include <pcap.h>

#include<stdio.h>
#include<windows.h>

#include "pcaplib.h"
#include "EtherCATlib.h"


void EthereCAT_SendRead(pcap_t* adhandle, EtherCATFrame_t* sendecat, EtherCATFrame_t* readecat)
{
    Framebuff_t ecat_frame;
    Framebuff_t ecat_hedder;
    Framebuff_t soccet;
    Framebuff_t send;
    char* Receive_packet;
    struct pcap_pkthdr* header;
    Framebuff_t rdata;

    if(readecat->DATA != NULL)
    {
        free(readecat->DATA);
        readecat->DATA = NULL;
    }
    
    //printf("-------- SEND --------\n");
    //EtherCAT_Frame_dump(sendecat);

    ethercat_build_fream(sendecat, &ecat_frame);
    ethercat_hedder_add_frame(&ecat_frame, &ecat_hedder);
    socket_add_fream(&ecat_hedder, &soccet);
    pcap_RawSend(adhandle, soccet.frame, soccet.length);
    free(soccet.frame);
    soccet.frame = NULL;

    //dump(soccet.frame, soccet.length);

    printf("-------- READ --------\n");
    if(pcap_RawReceive(adhandle, &header, &Receive_packet) != 0)
    {
        dump(Receive_packet, header->len);
        rdata.frame = Receive_packet;
        rdata.length = header->len;
        ethercat_decode_fream(&rdata, readecat);
    }//EtherCAT_Frame_dump(readecat);
    else
    {
        rdata.frame = NULL;
        rdata.length = 0;

    }
}

void EthereCAT_Reset(pcap_t* adhandle,uint16_t ADP )
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;

    uint16_t data =0;
    ethercat_frame_init(&sendecat);
    ethercat_frame_init(&readecat);

    data = 'R';
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0041;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    data = 'E';
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0041;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    data = 'S';
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0041;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

}


void EtherCAT_EEPROM_Setup(pcap_t* adhandle, uint16_t ADP)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;
    uint16_t data = 0;

    ethercat_frame_init(&sendecat);
    ethercat_frame_init(&readecat);

    data = 0x02;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0500;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    data = 0x00;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0500;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);


}

void EtherCAT_EEPROM_Status(pcap_t* adhandle, uint16_t ADP, uint8_t enable, uint8_t command)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;
    uint32_t data = 0;

    ethercat_frame_init(&sendecat);
    ethercat_frame_init(&readecat);


    data = command << 8 | enable;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0502;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);
    //free(readecat.DATA);

    for(int i=0;i<100;i++)
    {
    
        data = 0x0000;
        sendecat.CMD = EtherCAT_Command_APRD;
        sendecat.ADO = 0x0502;
        sendecat.ADP = ADP;
        sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
        sendecat.DATA[0] = data & 0xFF;
        sendecat.DATA[1] = (data >> 8) & 0xFF;
        sendecat.LEN = 2;

        EthereCAT_SendRead(adhandle, &sendecat, &readecat);
        if(readecat.LEN > 0)
        {
            data = readecat.DATA[0] & 0xFF | readecat.DATA[1] << 8;
            printf("0x%04X\n", data);
        }
        if ((data & 0x8000) == 0)
            return;
    }
    printf("EtherCAT EEPROM BusyError.\n");
    exit(1);



}

void EtherCAT_EEPROM_AddrSet(pcap_t* adhandle, uint16_t ADP, uint16_t addr)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;
    uint16_t data = 0;

    ethercat_frame_init(&sendecat);
    ethercat_frame_init(&readecat);


    data = addr;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0504;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

}

void EtherCAT_EEPROM_Read(pcap_t* adhandle, uint16_t ADP, EtherCATFrame_t *readecat)
{
    EtherCATFrame_t sendecat;
    
    uint16_t data = 0;

    ethercat_frame_init(&sendecat);
    ethercat_frame_init(readecat);

    data = 0x0000;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0508;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, readecat);

}

void EtherCAT_EEPROM_Write(pcap_t* adhandle, uint16_t ADP,uint16_t data)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;
    ethercat_frame_init(&sendecat);
    ethercat_frame_init(&readecat);

    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0508;
    sendecat.ADP = ADP;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

}



void EtherCAT_SetUp(pcap_t* adhandle, uint16_t ADP)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;
    uint16_t data;

    EtherCAT_EEPROM_Setup(adhandle, ADP);
    EtherCAT_EEPROM_Status(adhandle,ADP,0x00, 0x04);

    ethercat_frame_init(&sendecat);
    ethercat_frame_init(&readecat);

    sendecat.ADP = ADP;

    data = 0x0002;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0120;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    data = 0x0004;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0120;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    data = 0x0008;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0120;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

}

void EtherCAT_GPIOMode(pcap_t* adhandle, uint16_t ADP, uint32_t data)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;

    ethercat_frame_init(&sendecat);
    ethercat_frame_init(&readecat);

    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0F00;
    sendecat.ADP = ADP;
    sendecat.LEN = 4;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (sendecat.LEN));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.DATA[2] = (data >> 16) & 0xFF;
    sendecat.DATA[3] = (data >> 24) & 0xFF;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

}

void EtherCAT_GPIO_Out(pcap_t* adhandle, uint16_t ADP, uint32_t data)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;
    
    ethercat_frame_init(&sendecat);
    ethercat_frame_init(&readecat);

    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0F10;
    sendecat.LEN = 4;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (sendecat.LEN));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.DATA[2] = (data >> 16) & 0xFF;
    sendecat.DATA[3] = (data >> 24) & 0xFF;


    EthereCAT_SendRead(adhandle, &sendecat, &readecat);
  

}
