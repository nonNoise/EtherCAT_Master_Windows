
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
}EtherCATFrame_t;

typedef struct { 
	uint8_t frame[100];
	uint8_t length;
}Framebuff_t;





void dump(const unsigned char* data_buffer, const unsigned int length);


Framebuff_t ethercat_fream(EtherCATFrame_t ecat)
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
	
	//char tmp.frame[ecat.DataSize+13];
	Framebuff_t tmp;
	tmp.frame[0] = ecat.CMD;               			// CMD (1 byte)
	tmp.frame[1] = ecat.IDX;              			// IDX (1 byte)
	tmp.frame[2] = (ecat.ADP & 0xFF);       			// ADP (2 byte)
	tmp.frame[3] = (ecat.ADP & 0xFF00) >> 8;
	tmp.frame[4] = (ecat.ADO & 0xFF);      	  		// ADO (2 byte)
	tmp.frame[5] = (ecat.ADO & 0xFF00) >> 8;
	tmp.frame[6] = (ecat.DataSize & 0xFF);    		// LEN (2 byte)
	tmp.frame[7] = (ecat.DataSize & 0xFF00) >> 8;
	tmp.frame[8] = (ecat.IRQ & 0xFF);            	// IRQ (2 byte)
	tmp.frame[9] = (ecat.IRQ & 0x00FF);         		// IRQ (2 byte)
	for(int i=0;i<ecat.DataSize;i++){
		tmp.frame[10 + i] = ecat.DATA[i];
	}
	tmp.frame[10 + ecat.DataSize] = (ecat.WKC & 0xFF);    		// WKC (2 byte)
	tmp.frame[11 + ecat.DataSize] = (ecat.WKC & 0xFF00) >> 8;    // WKC (2 byte)
	tmp.length = 11 + ecat.DataSize+1;
	return tmp;
}


Framebuff_t ethercat_hedder_frame(int length)
{	
	Framebuff_t tmp;
	tmp.frame[0] = (11 + length);
	tmp.frame[1] = 0x10 | ((0x700 & (11 + length) ) >> 8);
	tmp.length = 2;
	return tmp;
}

Framebuff_t socket_fream(void)
{
	
	Framebuff_t socket_hedder;
	// send mac addr //
	socket_hedder.frame[0] = 0xff;
	socket_hedder.frame[1] = 0xff;
	socket_hedder.frame[2] = 0xff;
	socket_hedder.frame[3] = 0xff;
	socket_hedder.frame[4] = 0xff;
	socket_hedder.frame[5] = 0xff;
	// my mac addr //		
	socket_hedder.frame[6] = 0x01;
	socket_hedder.frame[7] = 0x01;
	socket_hedder.frame[8] = 0x01;
	socket_hedder.frame[9] = 0x01;
	socket_hedder.frame[10] = 0x01;
	socket_hedder.frame[11] = 0x01;
	// ethernet type //
	socket_hedder.frame[12] = 0x88;
	socket_hedder.frame[13] = 0xA4;
	socket_hedder.length = 14;
	return socket_hedder;
}

void frame_add(Framebuff_t *output,Framebuff_t input)
{
	for(int i=0;i<input.length;i++)
	{
		output->frame[i+output->length-1] = input.frame[i];
	}
	output->length = input.length+output->length;
}
/*
void send_frame()
{

	uint8_t frame[1500];
	



}
*/

/*
 def socket_read(self):
        recv = self.lowlevel.recv(1023)
        PDUframe = [0]*len(recv)
        for i in range(len(recv)):
            if(i >= 16):
                #print ('[{:d}]: 0x{:02x}'.format(i-16,recv[i]))
                PDUframe[i-16] = recv[i]

        CMD = PDUframe[0]              # CMD (1 byte)
        IDX = PDUframe[1]              # IDX (1 byte)
        ADP = PDUframe[2] | (PDUframe[3] << 8)      # ADP (2 byte)
        ADO = PDUframe[4] | (PDUframe[5] << 8)    # ADO (2 byte)
        LEN = PDUframe[6] | (PDUframe[7] << 8)    # LEN (2 byte)
        IRQ = PDUframe[8] | (PDUframe[9] << 8)    # IRQ (2 byte)
        DATA = [0] * LEN
        for i in range(LEN):
            #print ('[{:d}]: 0x{:02x}'.format(i,self_PDUfream[10+i]))
            DATA[i] = PDUframe[10 + i]
        # WKC (2 byte)
        WKC = PDUframe[9 + LEN + 1] | (PDUframe[9 + LEN + 2] << 8)
        #frame = [0] * 2
        #frame[0] = len(PDUframe)
        #frame[1] = 0x10 | ((0x700 & len(PDUframe)) >> 8)
        # print("-"*30)
        # print("CMD= 0x{:02x}".format(CMD))
        # print("IDX= 0x{:02x}".format(IDX))
        # print("ADP= 0x{:04x}".format(ADP))
        # print("ADO= 0x{:04x}".format(ADO))
        # print("LEN= 0x{:04x}".format(LEN))
        # print("IRQ= 0x{:04x}".format(IRQ))
        # for i in range(LEN):
        #    print ('DATA[%d]: 0x{:02X}'.format(DATA[i]) % (i))
        # print("WKC= 0x{:04x}".format(WKC))
        return (DATA, WKC)
*/
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