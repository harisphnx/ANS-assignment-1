#include<stdio.h>
#include<stdlib.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>   
#include<netinet/ip.h>    
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>

 
void print_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	printf("\n******************** Ethernet Header **********************\n");
	printf( "Destination Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	printf("Source Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	printf ("Protocol %u\n",(unsigned short)eth->h_proto); 
	if((unsigned short)eth->h_proto == 8)	
		printf("Protocol: IP\n");
	else if((unsigned short)eth->h_proto == 1544)
		printf("Protocol: ARP\n");
}
 
void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
    struct sockaddr_in source,dest;     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
     
    printf("\n***************** IP Header ****************\n");
    printf("IP Version        : %d\n",(unsigned int)iph->version);
    printf("IP Header Length  : %d Bytes\n",((unsigned int)(iph->ihl))*4);
    printf("Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("Identification    : %d\n",ntohs(iph->id));
    printf("Fragment offset    : %d\n",ntohs(iph->frag_off));
    printf("TTL      : %d\n",(unsigned int)iph->ttl);
    printf("Protocol : %d\n",(unsigned int)iph->protocol);
    printf("Checksum : %d\n",ntohs(iph->check));
    printf("Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf("Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iph->ihl*4 + sizeof(struct ethhdr));
     
    printf("\n************** TCP Header *****************\n");
    printf("Source Port      : %u\n",ntohs(tcph->source));
    printf("Destination Port : %u\n",ntohs(tcph->dest));
    printf("Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("Flags          : %d %d %d %d %d %d\n",(unsigned int)tcph->urg,(unsigned int)tcph->ack,(unsigned int)tcph->psh,(unsigned int)tcph->rst,(unsigned int)tcph->syn,(unsigned int)tcph->fin);
    printf("Window         : %d\n",ntohs(tcph->window));
    printf("Checksum       : %d\n",ntohs(tcph->check));
    printf("Urgent Pointer : %d\n",tcph->urg_ptr);
         
}

void print_udp_packet(unsigned char *Buffer , int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    struct udphdr *udph = (struct udphdr*)(Buffer + iph->ihl*4 + sizeof(struct ethhdr));
    printf("\n***********************UDP Packet*************************\n");
    printf("Source Port      : %d\n" , ntohs(udph->source));
    printf("Destination Port : %d\n" , ntohs(udph->dest));
    printf("Length       : %d\n" , ntohs(udph->len));
    printf("Checksum     : %d\n" , ntohs(udph->check));
}

int main()
{
	int data;
	struct sockaddr saddr;
	int saddr_size;
	unsigned char *buffer = (unsigned char *)malloc(65536);
	saddr_size = sizeof(saddr);
	data = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	while(1)
	{
		int size = recvfrom(data , buffer , 65536 , 0 , &saddr , &saddr_size);
		if ( size > 0 )
		{
			struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
			print_ethernet_header(buffer , size);
			print_ip_header(buffer, size);
			switch(iph->protocol)
			{
				case 6: //UDP
					print_udp_packet(buffer , size);
					break;
				case 17: //TCP
					print_tcp_packet(buffer , size);
					break;
			}
		}
	}
}

	

