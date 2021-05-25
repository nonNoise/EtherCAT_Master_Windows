
#include <stdio.h>
#include <pcap.h>

void main()
{
	printf("HELLO\n");
	pcap_if_t* alldevsp, * device;


	char errbuf[100];
	int count = 1;

	//First get the list of available devices
	printf("Finding available devices ... \n");
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		printf("Error finding devices : %s\n\n", errbuf);
		exit(1);
	}
	printf("Done\n");

	//Print the available devices
	printf("Available Devices are :\n");
	for (device = alldevsp; device != NULL; device = device->next)
	{
		printf("%d. %s - %s\n\n", count, device->name, device->description);
		count++;
	}
	while (1);
}