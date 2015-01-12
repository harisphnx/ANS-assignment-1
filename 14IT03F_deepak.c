#include<pcap.h>
#include<stdio.h>
#include<netinet/in.h>

#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<error.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#define ETHER_ADDR_LEN 6

struct sniff_ethernet{
			u_char ether_dhost[ETHER_ADDR_LEN];
			u_char ether_shost[ETHER_ADDR_LEN];
			u_short ether_type;
		};
struct sniff_ip{
			u_char ip_vhl;
			u_char ip_tos;
			u_short ip_len;
			u_short ip_id;
			u_short ip_offset;
		#define IP_RF 0x8000 // reserved flags
		#define IP_DF 0x4000 // not fragment flag
		#define IP_MF 0x2000 // more fragment flag
			u_char ip_ttl;
			u_char ip_p;	//protocol
			u_short ip_sum;  // checksum
			struct in_addr ip_src, ip_dst; //source and destination address
		};
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >>4)

typedef u_int tcp_seq;

struct sniff_tcp{
			u_short th_sport;
			u_short th_dport;
			tcp_seq	th_seq;
			tcp_seq th_ack;
			u_char th_offx2;
		#define TH_OFF(th)	(((th)->th_offx2 & 0xf0)>>4)
			u_char th_flags;
		#define TH_FIN	0x01
		#define TH_SYN	0x02
		#define TH_RST	0x04
		#define TH_PUSH	0x08
		#define TH_ACK	0x10
		#define TH_URG	0x20
		#define TH_ECE	0x40
		#define TH_CWR	0x80
		#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;	//window
		u_short th_sum;	//checksum
		u_short th_urp;	// urgent pointer
	};
#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;
	
	u_int size_ip;
	u_int size_tcp;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);


void print_hex_ascii_line(const u_char *payload, int len, int offset){
	int i;
	int gap;
	const u_char *ch;
	//offset
	printf("%05d	",offset);
	//hex
	ch = payload;
	for(i=0;i<len;i++)
	{
		printf("%02x",*ch);
		ch++;
		//print extra space after 8th bytes
		if(i==7)
			printf(" ");
	}
	//print space to handle line less than 8 byes long
	if(len <8)
		printf(" ");
	//fill hex gaps with spaces if not full line
	if(len<16){
			gap = 16-len;
			for(i=0;i<gap;i++)
			{
				printf(" ");
			}
		}
	printf(" ");
	//ascii if printable

	ch = payload;
	for (i=0;i<len;i++){
		if(isprint(*ch))
			printf("%c",*ch);
		else
			printf(".");
	ch++;
	}
	printf("\n");
	return;	
}

void print_payload(const u_char *payload, int len){
	int len_rem = len;
	int line_width = 16;
	int line_len;
	int offset=0;
	const u_char *ch = payload;

	if(len<=0)
		return;
	if(len<=line_width){
		print_hex_ascii_line(ch,len,offset);
		return;
	}
	for(;;)
	{
		line_len = line_width%len_rem;
		print_hex_ascii_line(ch,line_len,offset);
		
		len_rem = len_rem-line_len;
		
		ch = ch+line_len;
		
		offset = offset+line_width;
		
		if(len_rem <= line_width){
			print_hex_ascii_line(ch,len_rem,offset);
			break;
		}
	}
return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count=1;
	
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;
	
	printf("\nPacket number %d\n ",count);
	count++;
	
	ethernet= (struct sniff_ethernet *)(packet);
	ip = (struct sniff_ip *)(packet+SIZE_ETHERNET);
	size_ip=IP_HL(ip)*4;
	
	if(size_ip<20){
		printf("Invalid IP header length %u bytes \n",size_ip);
		return;
	}
	
	printf("\t from: %s\n",inet_ntoa(ip->ip_src));
	printf("\t to: %s\n", inet_ntoa(ip->ip_dst));
	
	switch(ip->ip_p){
		case IPPROTO_TCP :	printf("TCP protocol \n");
					break;
		case IPPROTO_UDP :	printf("UDP protocol \n");
					return;
		case IPPROTO_ICMP:	printf("ICMP protocol \n");
					return;
		case IPPROTO_IP	:	printf("IP PROTOCOL \n");
					return;
		default:
					printf("Unknown Protocol\n");
					return;
	}
	
	tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
	size_tcp = TH_OFF(tcp)*4;
	
	if(size_tcp<20)
	{
		printf("Invalid TCP header length : %u bytes\n",size_tcp);		  return;
	}
	
	printf("\t src port : %d\n",ntohs(tcp->th_sport));
	printf("\t dest port: %d\n",ntohs(tcp->th_dport));

	
return;
}
int  main(int argc, char **argv)
{
	pcap_t *handle;
	char *dev=NULL;
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[] = "tcp";
	bpf_u_int32 net;
	bpf_u_int32 mask;
	int num_packets=20;
	struct pcap_pkthdr header;
	const u_char *packet;
	
	if(argc ==2){
		dev = argv[1];
	}
	else if(argc >2){
		fprintf(stderr,"error:wrong inputs\n\n");
		return(2);
	}
	else {
		dev = pcap_lookupdev(errbuf);
		if(dev==NULL){
			fprintf(stderr,"couldn't found any device\n %s\n",errbuf);
			return(2);
		}
	}	
	
	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
		fprintf(stderr,"Couldn't get the mask of %s\nError : %s\n",dev,errbuf);
		net=0;
		mask=0;
	}
	
	printf("DEVICE NAME: %s\n",dev);
	printf("No of packets : %d\n",num_packets);
	printf("Filter exp : %s\n", filter_exp);

	handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		fprintf(stderr,"couldn't open the %s\nError : %s\n",dev,errbuf);
		return(2);
	}
	if(pcap_datalink(handle)!= DLT_EN10MB){
		fprintf(stderr,"%s is not a ethernet\n",dev);
		return(2);
	}
	if(pcap_compile(handle,&fp,filter_exp,0,net)==-1){
		fprintf(stderr,"couldn't parse filter %s: %s\n",filter_exp,pcap_geterr(handle));
		return(2);
	}
	if(pcap_setfilter(handle,&fp)==-1){
		fprintf(stderr,"couldn't install filter %s : %s \n",filter_exp,pcap_geterr(handle));
		return(2);
	}
	
	//grabing a packet
	
	//packet = pcap_next(handle,&header);
	pcap_loop(handle,num_packets,got_packet,NULL);
	
	pcap_freecode(&fp);
	pcap_close(handle);
	
	printf("\n\nCapture packet completes \n");
return 0;
}
