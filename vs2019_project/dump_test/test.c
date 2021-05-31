#include <string.h>
#include "EtherCATlib.h"



void main()
{

    EtherCATFrame_t ecatf;
    ecatf.CMD = EtherCAT_Command_APWR;
    ecatf.IDX = 0x00;
    ecatf.ADP = 0x00;
    ecatf.ADO = 0x0120;
    ecatf.C = 0x00;
    ecatf.NEXT = 0x00;
    ecatf.IRQ = 0x00;
    ecatf.DATA[0] = 0x0002;
    ecatf.DataSize = 1;
    ecatf.WKC = 8;
    
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

    //soccet = socket_fream();
    //frame_add(&send,soccet);
    //frame_add(&send,ecat_hedder);
    //frame_add(&send,ecat_frame);

    //printf("%d",send.length);
    //dump(cat_hedder.frame,cat_hedder.length);



/*
uint8_t CMD = 1;
uint8_t IDX = 1;
uint8_t ADP = 1;
uint8_t ADO = 1;
uint8_t C = 1;
uint8_t NEXT = 1;
uint8_t IRQ = 1;
char *DATA = "ABCD";
uint8_t WKC = 1;
build_socket(CMD,IDX,ADP,ADO,C,NEXT,IRQ,DATA,WKC);
*/

}