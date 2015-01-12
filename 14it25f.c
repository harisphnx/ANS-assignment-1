#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>


#define ELEN 6

#define IP_RF 	0x8000		
#define IP_DF 	0x4000		
#define IP_MF 	0x2000		
#define IP_OFFMASK 	0x1fff	
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_NS  0x100
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

struct ethernet {
		u_char ether_dhost[ELEN];
		u_char ether_shost[ELEN];
		u_short ether_type;
	};

struct ip {
		u_char ip_vhl;	
		u_char ip_tos;
		u_short ip_len;
		u_short ip_id;
		u_short ip_flags;
		u_short ip_off;		
		u_char ip_ttl;		
		u_char ip_p;		
		u_short ip_sum;		
		struct in_addr ip_src,ip_dst;
	};


struct tcp {
		u_short th_sport;	
		u_short th_dport;	
		u_int th_seq;		
		u_int th_ack;		
		u_char th_offx2;
		u_char th_flags;
		u_short th_win;		
		u_short th_sum;		
		u_short th_urp;		
};

struct udp {
	u_short	uh_sport;
	u_short	uh_dport;		
	u_short	uh_ulen;		
	u_short	uh_sum;			
};

FILE *output = NULL;

void printHaline(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	printf("\t\t\t%05d   ", offset);
	fprintf(output,"\t\t\t%05d   ", offset);
	
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		fprintf(output,"%02x ", *ch);
		ch++;
		if (i == 7){
			printf(" ");
			fprintf(output," ");
		}
	}
	if (len < 8){
		printf(" ");
		fprintf(output," ");
	}
	
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
			fprintf(output,"  ");
		}
	}
	printf("   ");
	fprintf(output,"   ");
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch)){
			printf("%c", *ch);
			fprintf(output,"%c", *ch);
		}
		else{
			printf(".");
			fprintf(output,".");
		}
		ch++;
	}

	printf("\n");
	fprintf(output,"\n");
	return;
}


void printPayload(const u_char *packet, int len)
{
	int len_rem = len;
	int line_width = 16;
	int line_len;
	int offset = 0;	
	const u_char *ch = packet;

	if (len <= 0)
		return;
	if (len <= line_width) {
		printHaline(ch, len, offset);
		return;
	}
	for ( ;; ) {
		line_len = line_width % len_rem;
		printHaline(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width){
			printHaline(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void processTcp(const u_char *packet,int size_ip, int ip_tot){

	const struct tcp *sniff_tcp = (struct tcp*)(packet + 14 + size_ip);
	const char *payload;
	int size_tcp;
	int size_payload;

	printf("\n\t\tTCP>>\n");
	printf("\t\t\tSRC_PRT  : %d DST_PRT : %d\n",ntohs(sniff_tcp->th_sport),ntohs(sniff_tcp->th_dport));
	printf("\t\t\tSEQ_NO : %d\n",sniff_tcp->th_seq);
	printf("\t\t\tACK_NO : %d\n",sniff_tcp->th_ack);
	printf("\t\t\tOFF : %d RESRVD : 000 NS : %d ECE : %d \n\t\t\tURG : %d ACK : %d PSH : %d RST : %d SYN : %d FIN : %d\n",TH_OFF(sniff_tcp),sniff_tcp->th_flags&TH_NS,sniff_tcp->th_flags&TH_ECE,sniff_tcp->th_flags&TH_URG,sniff_tcp->th_flags&TH_ACK,sniff_tcp->th_flags&TH_PUSH,sniff_tcp->th_flags&TH_RST,sniff_tcp->th_flags&TH_SYN,sniff_tcp->th_flags&TH_FIN);
	printf("\t\t\tWIN_SZE : %d CHK_SUM : %d URG_PTR : %d\n",sniff_tcp->th_win,sniff_tcp->th_sum,sniff_tcp->th_urp);
	

	fprintf(output,"\n\t\tTCP>>\n");
	fprintf(output,"\t\t\tSRC_PRT  : %d DST_PRT : %d\n",ntohs(sniff_tcp->th_sport),ntohs(sniff_tcp->th_dport));
	fprintf(output,"\t\t\tSEQ_NO : %d\n",sniff_tcp->th_seq);
	fprintf(output,"\t\t\tACK_NO : %d\n",sniff_tcp->th_ack);
	fprintf(output,"\t\t\tOFF : %d RESRVD : 000 NS : %d ECE : %d \n\t\t\tURG : %d ACK : %d PSH : %d RST : %d SYN : %d FIN : %d\n",TH_OFF(sniff_tcp),sniff_tcp->th_flags&TH_NS,sniff_tcp->th_flags&TH_ECE,sniff_tcp->th_flags&TH_URG,sniff_tcp->th_flags&TH_ACK,sniff_tcp->th_flags&TH_PUSH,sniff_tcp->th_flags&TH_RST,sniff_tcp->th_flags&TH_SYN,sniff_tcp->th_flags&TH_FIN);
	fprintf(output,"\t\t\tWIN_SZE : %d CHK_SUM : %d URG_PTR : %d\n",sniff_tcp->th_win,sniff_tcp->th_sum,sniff_tcp->th_urp);


	size_tcp = TH_OFF(sniff_tcp)*4;
	payload = (u_char *)(packet + 14 + size_ip + size_tcp);
	size_payload = ip_tot - (size_ip + size_tcp);
	printf("\t\t\tPAYLOAD>>\n");
	fprintf(output,"\n\t\t\tPAYLOAD>>\n");
	if(size_payload>0)	
		printPayload(payload,size_payload);
}

void processUdp(const u_char *packet, int size_ip,int ip_tot){
	const struct udp *sniff_udp = (struct udp*)(packet + 14 + size_ip);
	const char *payload;
	int size_tcp;
	int size_payload;
	printf("\n\t\tUDP>>\n");
	printf("\t\t\tSRC_PRT  : %d DST_PRT : %d\n",ntohs(sniff_udp->uh_sport),ntohs(sniff_udp->uh_dport));
	printf("\t\t\tLEN : %d\n",sniff_udp->uh_ulen);
	printf("\t\t\tCHKSUM : %d\n",sniff_udp->uh_sum);

	fprintf(output,"\n\t\tUDP>>\n");
	fprintf(output,"\t\t\tSRC_PRT  : %d DST_PRT : %d\n",ntohs(sniff_udp->uh_sport),ntohs(sniff_udp->uh_dport));
	fprintf(output,"\t\t\tLEN : %d\n",sniff_udp->uh_ulen);
	fprintf(output,"\t\t\tCHKSUM : %d\n",sniff_udp->uh_sum);

	payload = (u_char *)(packet + 14 + size_ip + 8);		//UDP header 8 bytes
	size_payload = ip_tot - (size_ip + 8);
	printf("\t\t\tPAYLOAD>>\n");
	fprintf(output,"\n\t\t\tPAYLOAD>>\n");
	if(size_payload>0)	
		printPayload(payload,size_payload);
	
}

void processIP(const u_char *packet){

	const struct ip *sniff_ip = (struct ip*)(packet + 14);
	int size_ip;
	size_ip = IP_HL(sniff_ip)*4;
	if(size_ip < 20){				//IPv4 check
		printf("Invalid IP version!!\n");
		return;
	}
	else{
		printf("\n\tIP>>\n");
		printf("\t\tVer   : %d IHL   : %d TOS : %d TOT_LEN : %d\n",
			IP_V(sniff_ip),IP_HL(sniff_ip),sniff_ip->ip_tos,sniff_ip->ip_len);
		printf("\t\tIDENT : %d FLAGS : %03X FRAG_OFF : %d\n",sniff_ip->ip_id,sniff_ip->ip_flags,sniff_ip->ip_off);
		printf("\t\tTTL : %d PROTOCOL : %d HDR_CHKSM : %d\n",sniff_ip->ip_ttl,sniff_ip->ip_p,sniff_ip->ip_sum);
		printf("\t\tSRC_IP  : %s\n",inet_ntoa(sniff_ip->ip_src));
		printf("\t\tDEST_IP : %s\n",inet_ntoa(sniff_ip->ip_dst));

		fprintf(output,"\n\tIP>>\n");
		fprintf(output,"\t\tVer   : %d IHL   : %d TOS : %d TOT_LEN : %d\n",
			IP_V(sniff_ip),IP_HL(sniff_ip),sniff_ip->ip_tos,sniff_ip->ip_len);
		fprintf(output,"\t\tIDENT : %d FLAGS : %03X FRAG_OFF : %d\n",sniff_ip->ip_id,sniff_ip->ip_flags,sniff_ip->ip_off);
		fprintf(output,"\t\tTTL : %d PROTOCOL : %d HDR_CHKSM : %d\n",sniff_ip->ip_ttl,sniff_ip->ip_p,sniff_ip->ip_sum);
		fprintf(output,"\t\tSRC_IP  : %s\n",inet_ntoa(sniff_ip->ip_src));
		fprintf(output,"\t\tDEST_IP : %s\n",inet_ntoa(sniff_ip->ip_dst));
	}
	
	if(sniff_ip->ip_p==IPPROTO_TCP){	//TCP
		processTcp(packet,size_ip,sniff_ip->ip_len);
		//exit(0);	
	}
	else if(sniff_ip->ip_p==IPPROTO_UDP){	//UDP
		processUdp(packet,size_ip,sniff_ip->ip_len);
		//exit(0);	
	}
		
}


void processEthernet(const u_char *packet){

	const struct ethernet *sniff_ethernet;
	int i,j;
	sniff_ethernet = (struct ethernet *) packet;

	printf("ETHERNET>>\n");
	printf("\tSRC  : ");
	
	fprintf(output,"ETHERNET>>\n");
	fprintf(output,"\tSRC  : ");

	for(i=0;i<6;i++){
		printf("%02X ",sniff_ethernet->ether_dhost[i]);
		fprintf(output,"%02X ",sniff_ethernet->ether_dhost[i]);
	}
	printf("\n");
	fprintf(output,"\n");
	printf("\tDEST : ");
	fprintf(output,"\tDEST : ");
	for(i=0;i<6;i++){
		printf("%02X ",sniff_ethernet->ether_shost[i]);
		fprintf(output,"%02X ",sniff_ethernet->ether_shost[i]);
		
	}
	printf("\n");
	printf("\tTYP  : %d\n",sniff_ethernet->ether_type);
	
	fprintf(output,"\n");
	fprintf(output,"\tTYP  : %d\n",sniff_ethernet->ether_type);
	if(sniff_ethernet->ether_type==8)			//IP check!
		processIP(packet);
}


int main()
{
	int i,j,seq=1;
	char *device = "eth0";
	pcap_t *session;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	struct pcap_pkthdr header;
	const char *payload;
	time_t nowtime;
	struct tm *nowtm;

	output = fopen("log.txt","w");
	
	session = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (session == NULL) {
		printf("Couldn't open device %s: %s\n", device, errbuf);
		return 0;
	 }

	while(1){
		packet = pcap_next(session, &header);
		printf("\n\nSEQ_NO      : %d\n",seq++);
		printf("Length      : %d\n",header.len);
    		printf("Recieved at : %s\n",ctime((const time_t*)& header.ts.tv_sec)); 
		
		fprintf(output,"\n\nSEQ_NO      : %d\n",seq-1);
		fprintf(output,"Length      : %d\n",header.len);
    		fprintf(output,"Recieved at : %s\n",ctime((const time_t*)& header.ts.tv_sec)); 
		processEthernet(packet);
		
	}	
	return 0;
}
