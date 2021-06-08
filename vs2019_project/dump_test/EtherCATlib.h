
//#include <pcap.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef EtherCATlib_H
#define EtherCATlib_H

// Auto increment physical read
#define EtherCAT_Command_APRD	 0x01
// Configured address physical read
#define EtherCAT_Command_FPRD	 0x04
//Broadcast read
#define EtherCAT_Command_BRD	 0x07
// Logical memory read
#define EtherCAT_Command_LRD	 0x0A
// Auto increment physical write
#define EtherCAT_Command_APWR	 0x02
// Configured address physical write
#define EtherCAT_Command_FPWR	 0x05
// Broadcast write
#define EtherCAT_Command_BWR	 0x08
// Logical memory write
#define EtherCAT_Command_LWR	 0x0B
// Auto increment physical read write
#define EtherCAT_Command_APRW	 0x03
// Configured address physical read write
#define EtherCAT_Command_FPRW	 0x06
// Configured address physical read write
#define EtherCAT_Command_BRW	 0x09
// Logical memory read write
#define EtherCAT_Command_LRW	 0x0C
// Auto increment physical read multiple write
#define EtherCAT_Command_ARMW	 0x0D
// Configured address physical read multiple write
#define EtherCAT_Command_FRMW	 0x0E

// int CMD: Command
// int IDX: Index
// int ADP: ADdress Position 16 bits (MSB half of 32bit)
// int ADO: ADdress Offset 16 bits (LSB half of 32 bit)
// int C:
// int NEXT:
// int IRQ:
// list DATA:
// int WKC: working counter	
typedef struct { 	
	uint8_t CMD;
	uint8_t IDX;
	uint16_t ADP;
	uint16_t ADO;
	uint16_t LEN;
	uint8_t C;
	uint8_t	NEXT;
	uint8_t	IRQ;
	uint8_t *DATA;
	uint8_t WKC;
}EtherCATFrame_t;

typedef struct { 
	uint8_t *frame;
	uint8_t length;
}Framebuff_t;


void dump(const unsigned char* data_buffer, const unsigned int length);


void ethercat_build_fream(EtherCATFrame_t *input,Framebuff_t *output)
{

	output->frame = (uint8_t *)malloc(sizeof(uint8_t) *  (11 + input->LEN +1) );
	output->frame[0] = input->CMD;               			// CMD (1 byte)
	output->frame[1] = input->IDX;              			// IDX (1 byte)
	output->frame[2] = (input->ADP & 0xFF);       			// ADP (2 byte)
	output->frame[3] = (input->ADP & 0xFF00) >> 8;
	output->frame[4] = (input->ADO & 0xFF);      	  		// ADO (2 byte)
	output->frame[5] = (input->ADO & 0xFF00) >> 8;
	output->frame[6] = (input->LEN & 0xFF);    				// LEN (2 byte)
	output->frame[7] = (input->LEN & 0xFF00) >> 8;
	output->frame[8] = (input->IRQ & 0xFF);            		// IRQ (2 byte)
	output->frame[9] = (input->IRQ & 0x00FF);         		// IRQ (2 byte)
	for(int i=0;i<input->LEN;i++){
		output->frame[10 + i] = input->DATA[i];
	}
	output->frame[10 + input->LEN] = (input->WKC & 0xFF);    		// WKC (2 byte)
	output->frame[11 + input->LEN] = (input->WKC & 0xFF00) >> 8;    // WKC (2 byte)
	output->length = 11 + input->LEN +1;
	//return *tmp;
}


void ethercat_hedder_add_frame(Framebuff_t *input,Framebuff_t *output)
{	
	output->frame = (uint8_t*)malloc(sizeof(uint8_t) *  (input->length+2));
	output->frame[0] = (11 + input->length);
	output->frame[1] = 0x10 | ((0x700 & (11 + input->length) ) >> 8);
	for(int i=0;i<input->length;i++)
	{
		output->frame[i+2] = input->frame[i];
	}
	output->length = (input->length+2);
	free(input->frame);
}

void socket_add_fream(Framebuff_t *input,Framebuff_t *output)
{
	
	output->frame = (uint8_t*)malloc(sizeof(uint8_t) *  (input->length+14));
	// send mac addr //
	output->frame[0] = 0xff;
	output->frame[1] = 0xff;
	output->frame[2] = 0xff;
	output->frame[3] = 0xff;
	output->frame[4] = 0xff;
	output->frame[5] = 0xff;
	// my mac addr //		
	output->frame[6] = 0x01;
	output->frame[7] = 0x01;
	output->frame[8] = 0x01;
	output->frame[9] = 0x01;
	output->frame[10] = 0x01;
	output->frame[11] = 0x01;
	// ethernet type //
	output->frame[12] = 0x88;
	output->frame[13] = 0xA4;
	for(int i=0;i<input->length;i++)
	{
		output->frame[i+14] = input->frame[i];
	}
	output->length = input->length+14;
	free(input->frame);

	//return output->frame.length;
}

void ethercat_decode_fream(Framebuff_t *input,EtherCATFrame_t *output)
{
	//dump(input->frame, input->length);
	
    output->CMD = input->frame[16+0];              // CMD (1 byte)
    output->IDX = input->frame[16+1];              // IDX (1 byte)
    output->ADP = input->frame[16+2] | (input->frame[16+3] << 8);    // ADP (2 byte)
    output->ADO = input->frame[16+4] | (input->frame[16+5] << 8);    // ADO (2 byte)
    output->LEN = input->frame[16+6] | (input->frame[16+7] << 8);    // LEN (2 byte)
    output->IRQ = input->frame[16+8] | (input->frame[16+9] << 8);    // IRQ (2 byte)
	output->DATA = (uint8_t*)malloc(sizeof(uint8_t) *  (output->LEN));
	for(int i=0;i<output->LEN;i++)
	{
        output->DATA[i] = input->frame[16+10 + i];
	}
    output->WKC = input->frame[16+9 + output->LEN + 1] | ( input->frame[9 + output->LEN + 2] << 8);	// WKC (2 byte)
        
}


void dump(const unsigned char* data_buffer, const unsigned int length)
{
	unsigned char byte;
	unsigned int i, j;
	printf("--------------------------------------------------------------------\n");
	for (i = 0; i < length; i++) {
		byte = data_buffer[i];
		printf(" %02x", data_buffer[i]);
		if ((i % 16 == 15) || (i == length - 1)) {
			for (j = 0; j < 15 - (i % 16); j++) {
				printf("   ");
			}
			printf("| ");
			for (j = (i - (i % 16)); j <= i; j++) {
				byte = data_buffer[j];
				if ((byte > 31) && (byte < 127))
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}


# endif