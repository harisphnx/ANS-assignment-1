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
    printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
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
    printf("IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf("TTL      : %d\n",(unsigned int)iph->ttl);
    printf("Protocol : %d\n",(unsigned int)iph->protocol);
    printf("Checksum : %d\n",ntohs(iph->check));
    printf("Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf("Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    printf("\n");
    printf("TCP Header\n");
    printf( "   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf( "   |-Window         : %d\n",ntohs(tcph->window));
    printf( "   |-Checksum       : %d\n",ntohs(tcph->check));
    printf( "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
         
 //   fprintf(logfile , "IP Header\n");
   // PrintData(Buffer,iphdrlen);
         
   // printf("TCP Header\n");
   // PrintData(Buffer+iphdrlen,tcph->doff*4);
         
  //  fprintf(logfile , "Data Payload\n");   
  //  PrintData(Buffer + header_size , Size - header_size );
       
}


int main()
{

	//int tcp_data , udp_data;
	int data;
	struct sockaddr saddr;
	int saddr_size;
	unsigned char *buffer = (unsigned char *)malloc(65536);
	saddr_size = sizeof(saddr);
	//tcp_data = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	//udp_data = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);
	data = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

	while(1)
	{
		int size = recvfrom(data , buffer , 65536 , 0 , &saddr , &saddr_size);
		
		if ( size > 0 )
		{
			struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	//		printf("in tcp %d\n", ((struct iphdr*)buffer)->protocol);
	//		print_tcp_packet(buffer , tcp_size);
	//	}			
			
    		print_ethernet_header(buffer , size);
		print_ip_header(buffer, size);
		switch(iph->protocol)
		{
			case 6: //UDP
				break;
			case 17: //TCP
				print_tcp_packet(buffer , size);
				break;
		}
		//udp_size = recvfrom(udp_data , buffer , 65536 , 0 , &saddr , &saddr_size);
		//if ( udp_size > 0 )
		//	printf("in udp %d\n", ((struct iphdr*)buffer)->protocol);
		}
	}
}

	

