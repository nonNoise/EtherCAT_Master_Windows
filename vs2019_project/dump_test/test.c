#include <string.h>
#include "EtherCATlib.h"



void main()
{

    EtherCATFream_t ecatf;

    ecatf.CMD = 1;
    ecatf.IDX = 2;
    ecatf.ADP = 3;
    ecatf.ADO = 4;
    ecatf.C = 5;
    ecatf.NEXT = 6;
    ecatf.IRQ = 7;
    ecatf.DATA = "ABCD";
    ecatf.DataSize = 2;
    ecatf.WKC = 8;
    build_socket(ecatf);

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