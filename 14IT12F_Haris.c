#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/ip.h>

#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

struct my_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        u_int th_seq;                 /* sequence number */
        u_int th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
	#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
	#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
	#define	IP_DF 0x4000			/* dont fragment flag */
	#define	IP_MF 0x2000			/* more fragments flag */
	#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

int handle_tcp(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet, int hlen, int len)
{
	const struct my_tcp *tcp;
	const char *payload;
	
	int size_ip = hlen*4;
	int size_tcp;
	int size_payload;

	tcp = (struct my_tcp*)(packet + ETHER_HDRLEN + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20)
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("Src port: %d\n", ntohs(tcp->th_sport));
	printf("Dst port: %d\n", ntohs(tcp->th_dport));
	printf("Seq number: %d\n", tcp->th_seq);
	printf("Ack number: %d\n", tcp->th_ack);
	printf("Window: %d\n", ntohs(tcp->th_win));
	printf("Checksum: %d\n", ntohs(tcp->th_sum));
	printf("Urg Pointer: %d\n", ntohs(tcp->th_urp));
	
	/* define/compute tcp payload (segment) offset */
	//payload = (u_char *)(packet + ETHER_HDRLEN + size_ip + size_tcp);
	/* compute tcp payload (segment) size */
	//size_payload = ntohs(len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	/*if (size_payload > 0)
	{
		printf("   Payload (%d bytes):\n", size_payload);
		//print_payload(payload, size_payload);
	}*/
	return 0;
}

u_char* handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	const struct my_ip* ip;
    	u_int length = pkthdr->len;
	u_int hlen,off,version;
    	int i;
	int len;

    	/* jump pass the ethernet header */
    	ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    	length -= sizeof(struct ether_header); 

    	/* check to see we have a packet of valid length */
    	if (length < sizeof(struct my_ip))
    	{
        	printf("truncated ip %d",length);
        	return NULL;
    	}

    	len     = ntohs(ip->ip_len);
    	hlen    = IP_HL(ip); /* header length */
    	version = IP_V(ip);/* ip version */

    	/* check version */
    	if(version != 4)
    	{
      		fprintf(stdout,"Unknown version %d\n",version);
      		return NULL;
    	}

    	/* check header length */
    	if(hlen < 5 )
    	{
        	fprintf(stdout,"bad-hlen %d \n",hlen);
    	}

    	/* see if we have as much packet as we should */
    	if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    	/* Check to see if we have the first fragment */
    	off = ntohs(ip->ip_off);
    	if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    	{/* print SOURCE DESTINATION hlen version len offset */
        	fprintf(stdout,"\nIP Header:\n");
        	fprintf(stdout,"Source IP: %s\n",inet_ntoa(ip->ip_src));
        	fprintf(stdout,"Dest IP: %s\n", inet_ntoa(ip->ip_dst));
		fprintf(stdout,"version: %d\nhlen: %d\nTOS: %d\ntotal_length: %d\n", version, hlen, ip->ip_tos, len);
		fprintf(stdout,"Time_to_live: %d\nProtocol: %d\nChecksum: %d\n", ip->ip_ttl, ip->ip_p, ip->ip_sum);

    	}

	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			handle_tcp(args, pkthdr, packet, hlen, len);
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("Protocol: IP\n");
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}

    	return NULL;
}

u_int16_t handle_ethernet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	struct ether_header *eptr;  /* net/ethernet.h */
    
	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;
	fprintf(stdout,"\n\n\nEthernet Packet\nSource: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
	fprintf(stdout,"Destination: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

	/* check to see if we have an ip packet */
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
	{
        	fprintf(stdout,"IP Packet");
		handle_IP(args,pkthdr,packet);
	}
	else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    	{
        	fprintf(stdout,"ARP Packet");
    	}
	else  if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP)
    	{
        	fprintf(stdout,"RARP Packet");
    	}
	else 
	{
        	fprintf(stdout,"Unknown Packet");
        	//exit(1);
    	}
    	return eptr->ether_type;
}

void show_details(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	u_int16_t type = handle_ethernet(useless,pkthdr,packet);
}

int main()
{
	char * dev;
	char err_buf[1024];
	pcap_t* descr;
	dev = pcap_lookupdev(err_buf);
	descr = pcap_open_live("eth2",BUFSIZ,0,100000000,err_buf);
	pcap_loop(descr,-1,show_details,NULL);
}
