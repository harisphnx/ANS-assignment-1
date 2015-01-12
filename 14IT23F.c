#include<stdio.h> 
#include<stdlib.h>
#include<string.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>

void checkProtocolType(unsigned char* , int);
void processIPHeader(unsigned char* , int);
void processTCPPacket(unsigned char* , int);
void processUDPPacket(unsigned char * , int);
 
int sock_raw;
FILE *outputfile;
int tcp=0,udp=0,i,j;
struct sockaddr_in source,dest;

int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
     
    unsigned char *buffer = (unsigned char *)malloc(65536);
     
    outputfile=fopen("output.txt","w");
    if(outputfile==NULL) printf("Unable to create file.");
    printf("Started capturing the packets,packet details of captured packets are stored in file output.txt.\n");
   
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
     
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Got error from resvfrom function....\n");
            return 1;
        }
        checkProtocolType(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}

void processEthernetFrame(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	fprintf(outputfile,"Ethernet Header\n");
	fprintf(outputfile,"  Destination Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(outputfile,"  Source Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf (outputfile,"  Protocol %u\n",(unsigned short)eth->h_proto); 
	if((unsigned short)eth->h_proto == 8)	
		fprintf(outputfile,"Protocol: IP\n");
	else if((unsigned short)eth->h_proto == 1544)
		fprintf(outputfile,"Protocol: ARP\n");
}

void checkProtocolType(unsigned char* buffer, int size)
{
    struct iphdr *iph = (struct iphdr*)buffer;
    switch (iph->protocol)
    {
         
        case 6:
            ++tcp;
            processTCPPacket(buffer , size);
            break;
         
        case 17:
            ++udp;
            processUDPPacket(buffer , size);
            break;
    }
    printf("Number of TCP and UDP Packets are : %d  %d\r",tcp,udp);
}
 
void processIPHeader(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(outputfile,"\n");
    fprintf(outputfile,"IP Header\n");
    fprintf(outputfile,"  Version        : %d\n",(unsigned int)iph->version);
    fprintf(outputfile,"  Header Length  : %d %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(outputfile,"  Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(outputfile,"  Total Length   : %d  Bytes\n",ntohs(iph->tot_len));
    fprintf(outputfile,"  Identification    : %d\n",ntohs(iph->id));
    fprintf(outputfile,"  TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(outputfile,"  Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(outputfile,"  Checksum : %d\n",ntohs(iph->check));
    fprintf(outputfile,"  Source IP Address        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(outputfile,"  Destination IP Address   : %s\n",inet_ntoa(dest.sin_addr));
}
 
void processTCPPacket(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcpHeader=(struct tcphdr*)(Buffer + iphdrlen);
             
    fprintf(outputfile,"\n\n---------TCP Packet---------\n");    
    processEthernetFrame(Buffer,Size);
    processIPHeader(Buffer,Size);
         
    fprintf(outputfile,"\n");
    fprintf(outputfile,"TCP Header\n");
    fprintf(outputfile," Source Port      : %u\n",ntohs(tcpHeader->source));
    fprintf(outputfile," Destination Port : %u\n",ntohs(tcpHeader->dest));
    fprintf(outputfile," Sequence Number    : %u\n",ntohl(tcpHeader->seq));
    fprintf(outputfile," Acknowledge Number : %u\n",ntohl(tcpHeader->ack_seq));
    fprintf(outputfile," Header Length      : %d %d BYTES\n" ,(unsigned int)tcpHeader->doff,(unsigned int)tcpHeader->doff*4);
    fprintf(outputfile," Urgent Flag          : %d\n",(unsigned int)tcpHeader->urg);
    fprintf(outputfile," Acknowledgement Flag : %d\n",(unsigned int)tcpHeader->ack);
    fprintf(outputfile," Push Flag            : %d\n",(unsigned int)tcpHeader->psh);
    fprintf(outputfile," Reset Flag           : %d\n",(unsigned int)tcpHeader->rst);
    fprintf(outputfile," Synchronise Flag     : %d\n",(unsigned int)tcpHeader->syn);
    fprintf(outputfile," Finish Flag          : %d\n",(unsigned int)tcpHeader->fin);
    fprintf(outputfile," Window         : %d\n",ntohs(tcpHeader->window));
    fprintf(outputfile," Checksum       : %d\n",ntohs(tcpHeader->check));
    fprintf(outputfile," Urgent Pointer : %d\n",tcpHeader->urg_ptr);
    fprintf(outputfile,"\n");
                         
    fprintf(outputfile,"\n---------------------------------------");
}
 
void processUDPPacket(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udpHeader = (struct udphdr*)(Buffer + iphdrlen);
     
    fprintf(outputfile,"\n\n---------UDP Packet---------\n");
    processEthernetFrame(Buffer,Size);
    processIPHeader(Buffer,Size);           
     
    fprintf(outputfile,"\nUDP Header\n");
    fprintf(outputfile,"   Source Port      : %d\n" , ntohs(udpHeader->source));
    fprintf(outputfile,"   Destination Port : %d\n" , ntohs(udpHeader->dest));
    fprintf(outputfile,"   UDP Length       : %d\n" , ntohs(udpHeader->len));
    fprintf(outputfile,"   UDP Checksum     : %d\n" , ntohs(udpHeader->check));
     
    fprintf(outputfile,"\n");
    fprintf(outputfile,"\n---------------------------------------");
}
