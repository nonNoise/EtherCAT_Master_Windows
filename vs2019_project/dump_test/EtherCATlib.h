
//#include <pcap.h>
#include <string.h>
#include <stdint.h>


typedef struct { 
	uint8_t CMD;
	uint8_t IDX;
	uint8_t ADP;
	uint8_t ADO;
	uint8_t C;
	uint8_t	NEXT;
	uint8_t	IRQ;
	char 	*DATA;
	uint16_t	DataSize;
	uint8_t WKC;
}EtherCATFream_t;


void dump(const unsigned char* data_buffer, const unsigned int length);

void build_socket(EtherCATFream_t ecat)
{
    /*
        :param int CMD: Command
        :param int IDX: Index
        :param int ADP: ADdress Position 16 bits (MSB half of 32bit)
        :param int ADO: ADdress Offset 16 bits (LSB half of 32 bit)
        :param int C:
        :param int NEXT:
        :param int IRQ:
        :param list DATA:
        :param int WKC: working counter
	*/
	
	char socket_hedder[14];
	// send mac addr //
	socket_hedder[0] = 0xff;
	socket_hedder[1] = 0xff;
	socket_hedder[2] = 0xff;
	socket_hedder[3] = 0xff;
	socket_hedder[4] = 0xff;
	socket_hedder[5] = 0xff;
	// my mac addr //		
	socket_hedder[6] = 0x01;
	socket_hedder[7] = 0x01;
	socket_hedder[8] = 0x01;
	socket_hedder[9] = 0x01;
	socket_hedder[10] = 0x01;
	socket_hedder[11] = 0x01;
	// ethernet type //
	socket_hedder[12] = 0x88;
	socket_hedder[13] = 0xA4;

	char Frame[ecat.DataSize+13];
        Frame[0] = ecat.CMD;               			// CMD (1 byte)
        Frame[1] = ecat.IDX;              			// IDX (1 byte)
        Frame[2] = (ecat.ADP & 0xFF);       			// ADP (2 byte)
        Frame[3] = (ecat.ADP & 0xFF00) >> 8;
        Frame[4] = (ecat.ADO & 0xFF);      	  		// ADO (2 byte)
        Frame[5] = (ecat.ADO & 0xFF00) >> 8;
        Frame[6] = (ecat.DataSize & 0xFF);    		// LEN (2 byte)
        Frame[7] = (ecat.DataSize & 0xFF00) >> 8;
        Frame[8] = (ecat.IRQ & 0xFF);            	// IRQ (2 byte)
        Frame[9] = (ecat.IRQ & 0x00FF);         		// IRQ (2 byte)
		for(int i=0;i<ecat.DataSize;i++){
            Frame[10 + i] = ecat.DATA[i];
		}
		Frame[10 + ecat.DataSize] = (ecat.WKC & 0xFF);    		// WKC (2 byte)
        Frame[11 + ecat.DataSize] = (ecat.WKC & 0xFF00) >> 8;    // WKC (2 byte)


	char frame_hedder[2];
	frame_hedder[0] = (11 + ecat.DataSize);
	frame_hedder[1] = 0x10 | ((0x700 & (11 + ecat.DataSize) ) >> 8);

	char socket[14+2+ecat.DataSize+13];
	for(int i=0;i<14;i++)
		socket[i] = socket_hedder[i];
	for(int i=0;i<2;i++)
		socket[14+i] = frame_hedder[i];
	for(int i=0;i<(ecat.DataSize+13);i++)
		socket[14+2+i] = Frame[i];

	dump(socket,14+2+ecat.DataSize+13);

}


void dump(const unsigned char* data_buffer, const unsigned int length)
{
	unsigned char byte;
	unsigned int i, j;
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