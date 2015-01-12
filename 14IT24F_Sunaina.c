#include<stdio.h> 
#include<stdlib.h>    
#include<string.h>    
#include<netinet/ip_icmp.h>   
#include<netinet/udp.h>   
#include<netinet/tcp.h>   
#include<netinet/ip.h>    
#include<sys/socket.h>
#include<arpa/inet.h>
 
void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
void PrintData (unsigned char* , int);
 
int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
 
int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
     
    unsigned char *buffer = (unsigned char *)malloc(65536); 
     
    //logfile=fopen("log.txt","w");
    //if(logfile==NULL) printf("File not created.");
    //printf("Wait\n");
    
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Unable to create socket...Socket Error\n");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished doing it...");
    return 0;
}
 
void ProcessPacket(unsigned char* buffer, int size)
{
    
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) 
    {
        case 6:  
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
         
        case 17: 
            ++udp;
            print_udp_packet(buffer , size);
            break;
         
        default: 
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   Others : %d   Total : %d\r",tcp,udp,others,total);
}
 
void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    //printf(logfile,"\n");
    printf("IP Header\n");
    printf("  IP Version        : %d\n",(unsigned int)iph->version);
    printf("  IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("  Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("  IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("  Identification    : %d\n",ntohs(iph->id));
    printf("  TTL      : %d\n",(unsigned int)iph->ttl);
    printf("  Protocol : %d\n",(unsigned int)iph->protocol);
    printf("  Checksum : %d\n",ntohs(iph->check));
    printf("  Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf("  Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}
 
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
             
    printf("\n\n***********************TCP Packet*************************\n");    
         
    print_ip_header(Buffer,Size);
         
    printf("\n");
    printf("TCP Header\n");
    printf("  Source Port      : %u\n",ntohs(tcph->source));
    printf("  Destination Port : %u\n",ntohs(tcph->dest));
    printf("  Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("  Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("  Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    printf("  Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("  Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("  Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("  Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("  Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("  Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("  Window         : %d\n",ntohs(tcph->window));
    printf("  Checksum       : %d\n",ntohs(tcph->check));
    printf("  Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");
         
    printf("IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    printf("TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    printf("Data Payload\n");  
    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
                         
   printf("\n###########################################################");
}
 
void print_udp_packet(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
     
    printf("\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);           
     
    printf("\nUDP Header\n");
    printf("  Source Port      : %d\n" , ntohs(udph->source));
    printf("  Destination Port : %d\n" , ntohs(udph->dest));
    printf("  UDP Length       : %d\n" , ntohs(udph->len));
    printf("  UDP Checksum     : %d\n" , ntohs(udph->check));
     
    printf("\n");
    printf("IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    printf("UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    printf("Data Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));
     
    printf("\n###########################################################");
}
void PrintData (unsigned char* data , int Size)
{
     
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); 
                 
                else printf("."); 
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  
        {
            for(j=0;j<15-i%16;j++) printf("   "); 
             
            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}
