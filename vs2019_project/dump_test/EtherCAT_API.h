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



    printf("-------- SEND --------\n");
    EtherCAT_Frame_dump(sendecat);

    ethercat_build_fream(sendecat, &ecat_frame);
    ethercat_hedder_add_frame(&ecat_frame, &ecat_hedder);
    socket_add_fream(&ecat_hedder, &soccet);
    pcap_RawSend(adhandle, soccet.frame, soccet.length);
    //dump(soccet.frame, soccet.length);

    pcap_RawReceive(adhandle, &header, &Receive_packet);
    //dump(Receive_packet, header->len);
    rdata.frame = Receive_packet;
    rdata.length = header->len;
    ethercat_decode_fream(&rdata, readecat);
    printf("-------- READ --------\n");
    EtherCAT_Frame_dump(readecat);
}

void EthereCAT_Reset(pcap_t* adhandle,uint16_t ADP )
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;

    uint16_t data =0;
    data = 'R';
    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

    data = 'R';
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0041;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    data = 'E';
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0041;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    data = 'S';
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0041;
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

    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

    data = 0x02;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0500;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    data = 0x00;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0500;
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
    uint16_t data = 0;

    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

    data = command << 8 | enable;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0502;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

    while (1)
    {
    
        data = 0x0000;
        sendecat.CMD = EtherCAT_Command_APWR;
        sendecat.ADO = 0x0502;
        sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
        sendecat.DATA[0] = data & 0xFF;
        sendecat.DATA[1] = (data >> 8) & 0xFF;
        sendecat.LEN = 2;

        EthereCAT_SendRead(adhandle, &sendecat, &readecat);
        data = readecat.DATA[0] & 0xFF | readecat.DATA[1] << 8;
        if (data & 0x8000 == 0)
            break;
    }



}

void EtherCAT_EEPROM_AddrSet(pcap_t* adhandle, uint16_t ADP, uint16_t addr)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;
    uint16_t data = 0;

    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

    data = addr;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0504;
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

    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

    data = 0x0000;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0508;
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

    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0508;
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
    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

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

void EtherCAT_GPIOMode(pcap_t* adhandle, uint16_t ADP, uint16_t data)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;

    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0F00;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

}

void EtherCAT_GPIO_Out(pcap_t* adhandle, uint16_t ADP, uint16_t data)
{
    EtherCATFrame_t sendecat;
    EtherCATFrame_t readecat;
    

    sendecat.CMD = 0x0000;
    sendecat.ADO = 0x0000;
    sendecat.ADP = ADP;
    sendecat.IDX = 0x00;
    sendecat.ADP = 0x00;
    sendecat.C = 0x00;
    sendecat.NEXT = 0x00;
    sendecat.IRQ = 0x00;
    sendecat.WKC = 0x00;
    sendecat.DATA = NULL;
    sendecat.LEN = 0;

    data = 0x0F00;
    sendecat.CMD = EtherCAT_Command_APWR;
    sendecat.ADO = 0x0F10;
    sendecat.DATA = (uint8_t*)malloc(sizeof(uint8_t) * (2));
    sendecat.DATA[0] = data & 0xFF;
    sendecat.DATA[1] = (data >> 8) & 0xFF;
    sendecat.LEN = 2;

    EthereCAT_SendRead(adhandle, &sendecat, &readecat);

}
