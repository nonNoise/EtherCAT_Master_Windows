#include <string.h>
#include "EtherCATlib.h"



void main()
{

    EtherCATFrame_t ecatf;
    ecatf.CMD = 1;
    ecatf.IDX = 2;
    ecatf.ADP = 3;
    ecatf.ADO = 4;
    ecatf.C = 5;
    ecatf.NEXT = 6;
    ecatf.IRQ = 7;
    ecatf.DATA = "ABCD";
    ecatf.DataSize = 4;
    ecatf.WKC = 8;
    
    Framebuff_t ecat_frame;
    Framebuff_t ecat_hedder;
    Framebuff_t soccet;
    Framebuff_t send;
    
    ecat_frame = ethercat_fream(ecatf);
    ecat_hedder = ethercat_hedder_frame(ecat_frame.length);
    soccet = socket_fream();
    frame_add(&send,soccet);
    frame_add(&send,ecat_hedder);
    frame_add(&send,ecat_frame);

    //printf("%d",send.length);
    dump(send.frame,send.length);


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