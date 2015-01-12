
#include<stdio.h>
#include<pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>

int count=0;

struct ethernet_header
{
	u_char dmac[6];
	u_char smac[6];
	u_short etype;
};

struct ip_header
{
	u_char verandlen;
	u_char tos;
	u_short totaleln;
	u_short id;
	u_short offset;
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ttl;		
	u_char protocol;		/* upper layer protocol */
	u_short checksum;		
	struct in_addr ip_src;
	struct in_addr ip_dst; 
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)    //??
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)	   //??

typedef u_int tcp_seq;

struct tcp_header 
{
	u_short sport;	
	u_short dport;	
	tcp_seq seqnum;		
	tcp_seq acknum;		
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short window;		/* window */
	u_short checksum;		/* checksum */
	u_short urgent_pointer;		/* urgent pointer */
};
















void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	printf("\n-------------------------------------------------");
	//printf("\nIn callback!!...");

	const struct ethernet_header *eh;
	const struct ip_header *ih;
	const struct tcp_header *th;
	const char *payload;
	
	u_int ip_header_len;
	u_int tcp_header_len;

	eh=(struct ethernet_header *)(packet);
	ih=(struct ip_header *)(packet+14);
	th=(struct tcp_header *)(packet+20);
	payload=(u_char *)(packet+14+20+20);

	
	
	if(eh->etype == 8)
	{
	
		count=count+1;
		printf("\nCount = %d",count);
		printf("\nEthernet Type --> %u", eh->etype);
		
		//printf("\nSource MAC Address --> %s",eh->dmac);
		//printf("\nDestination MAC Address --> %s",eh->smac);

		//print("\nSource IP Address --> %s

		printf("\nTCP Source Port --> %u", th->sport);
		printf("\nTCP Destination Port --> %u", th->dport);



	}	

}


int main(int argc, char *argv[])
{
	
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header; // used for capturing the packet
	const u_char *packet; 	// used for capturing the packet
	int temp;


	//look up for device to sniff on
	device = pcap_lookupdev(error_buffer);

	if(device != NULL)
	{
		printf("Device Selected for sniffing : %s\n", device);
		
	}

	else
	{
		printf("Problem with the 'pcap_lookupdev' function : %s\n", error_buffer);
		return 2;
	}


	// open that device for starting the capture, notice that you are opening the deivce in promiscous mode!!!
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer); // 1-> Promiscous mode, 1000-> Wait for 1000ms 

	if(handle == NULL )
	{
		printf("Some problem with 'pcap_open_live' function : %s\n", error_buffer);
		return 2;
	}
	
	//Check if link layer protocol is infact "Ethernet" !!
	if(pcap_datalink(handle) != DLT_EN10MB)
	{
		printf("This program handles only Ethernet data, while the underlying link is not the one\n");
		return 2;
	}

	
	//Capture a Packet!!  am i doing this actually??!!
	//packet=pcap_next(handle, &header);
	//printf("I captured a packet, you dont believe me!!, Its length is %d\n", header.len);

	
	// Let me capture 'n' packets!!
	temp=pcap_loop(handle, -1, process_packet,NULL);

	
	
	





	// CLosing the live capture session!! finally...
	pcap_close(handle);

	return 0;
	

		







}
	
