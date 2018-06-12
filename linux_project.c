#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*Ethernet Header*/
typedef struct ethernet_header
{
	u_char dest[6];
	u_char source[6];
	u_short type;
}   ethernet_header;

/*Logical Link Control*/
typedef struct llc_header
{
	u_char DSAP[1];
	u_char SSAP[1];
	u_short CF;	//control field
}	llc_header;

int number;

int main(int argc, char **argv) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ether dst FFFFFFFFFFFF and ether src 01606e11020f";
	struct bpf_program fcode;

	//struct pcap_addr *a;

	
	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("Error in pcap_findalldevs\n");
		return 1;
	}

	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if(d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	/* Print the list */
	printf("Enter the interface number (1-%d): ", i);
	scanf("%d", &inum);

	/*error interface number*/
	if (!(inum > 0 && inum <= i)) {
		printf("\nInterface number out of range.\n\n");
		return 1;
	}

	/* Jump to the selected adapter */
	for (d=alldevs, i=0; i< inum -1; d = d->next, i++);

	/* Open the device */
	if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
		printf("pcap_open_live error %s\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//if (d->addresses != NULL)
	if (d->addresses->netmask != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.s_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		printf("\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		printf("\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	

	printf("\nlistening on %s...\n", d->name);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	//printf("Number of Packets: \r");
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ethernet_header *ethh;
	llc_header *llch;
	int llclen;
	u_char *data;

	int i=0;
	/*digest packet*/
	//Ethernet header
	ethh = (ethernet_header *)pkt_data;
	
	//Ip packets
	if (ntohs(ethh->type) == 0x002e)
	{
		//PrintOtherPacket(pkt_data, header->caplen);
		llch = (llc_header*)(pkt_data + sizeof(ethernet_header));
		llclen = sizeof(llc_header);

		number++;
		printf("#####################No.%d Packet#####################", number);

		data = ((u_char*)pkt_data + sizeof(ethernet_header));
		int data_size = (header->caplen - sizeof(ethernet_header));

		printf("\n");
		printf("Ethernet Header\n");
		printf(" |-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethh->dest[0], ethh->dest[1], ethh->dest[2], ethh->dest[3], ethh->dest[4], ethh->dest[5]);
		printf(" |-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethh->source[0], ethh->source[1], ethh->source[2], ethh->source[3], ethh->source[4], ethh->source[5]);
		printf(" |-Protocol		: 0x%.4x \n", ntohs(ethh->type));
		printf(" |-DSAP			: %.2X \n", llch->DSAP[0]);
		printf(" |-SSAP			: %.2X \n", llch->SSAP[0]);
		printf(" |-Control field	: 0x%.4x \n", ntohs(llch->CF));
		printf("\nData Payload\n");

		for (i = 0; i < data_size; i++) {		//last bit is for error check, so erase
													//hex
			printf("%.2x ", (unsigned int)data[i]);
			if (i % 6 == 5) {
				printf("\n");
			}
		}
		printf("\n");
		
		for (i = 0; i < data_size; i++) {
			//character
			printf("%c", data[i]);
		}
		
		printf("\n");

		int result;
		int addition;
		for (i = 4; i < 8; i++) {
			//result
			switch (i) {
			case 4:
				result = data[i];
				result = result << 24;
				break;
			case 5:
				addition = data[i];
				addition = addition << 16;
				result += addition;
				break;
			case 6:
				addition = data[i];
				addition = addition << 8;
				result += addition;
				break;
			case 7:
				addition = data[i];
				result += addition;
				break;
			
			default:
				break;
			}
		}
				
		double result2 = result;
		printf("result: %.5e\n", (result2 / 100000000));

		printf("\n\n#####################################################\n\n");
	}
}

