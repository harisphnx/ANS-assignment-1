#include<stdio.h> 
#include<stdlib.h>
#include<string.h>
#include<netinet/udp.h>  
#include<netinet/tcp.h>  
#include<netinet/ip.h>   
#include<sys/socket.h>
#include<arpa/inet.h>
void read(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void tcppkt(unsigned char* , int);
void udppkt(unsigned char * , int);
void disp (unsigned char* , int);
int sock;
FILE *fp;
int tcp=0,udp=0,x=0,i,j;
struct sockaddr_in source,dest;
 
int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    fp=fopen("abc.txt","w");
    if(fp==NULL) printf("Unable to create file.");
    printf("Starting...\n");
    sock = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        read(buffer , data_size);
    }
    close(sock);
    printf("Finished");
    return 0;
}
 
void read(unsigned char* buffer, int size)
{
    struct iphdr *iph = (struct iphdr*)buffer;
    switch (iph->protocol)
    {     
        case 6:  
            ++tcp;
            tcppkt(buffer , size);
            break;
         
        case 17: 
            ++udp;
            udppkt(buffer , size);
            break;
         
        default: 
            ++x;
            break;
    }
    printf("TCP : %d  \n UDP : %d  ",tcp,udp);
}
 
void print_ip_header(unsigned char* Buffer, int max)
{
    unsigned short iphdrlen;     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(fp,"\n");
    fprintf(fp,"IP Header\n");
    fprintf(fp,"   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(fp,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(fp,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(fp,"   |-IP Total Length   : %d  Bytes(max of Packet)\n",ntohs(iph->tot_len));
    fprintf(fp,"   |-Identification    : %d\n",ntohs(iph->id));
    
    fprintf(fp,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(fp,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(fp,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(fp,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(fp,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}
 
void tcppkt(unsigned char* Buffer, int max)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
    fprintf(fp,"\n\n***********************TCP Packet*************************\n");    
    print_ip_header(Buffer,max);
    fprintf(fp,"\n");
    fprintf(fp,"TCP Header\n");
    fprintf(fp,"   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(fp,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(fp,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(fp,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(fp,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(fp,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(fp,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(fp,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(fp,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(fp,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(fp,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(fp,"   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(fp,"   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(fp,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(fp,"\n");
    fprintf(fp,"                        DATA Dump                         ");
    fprintf(fp,"\n");
    fprintf(fp,"IP Header\n");
    disp(Buffer,iphdrlen);
    fprintf(fp,"TCP Header\n");
    disp(Buffer+iphdrlen,tcph->doff*4);
    fprintf(fp,"Data Payload\n");  
    disp(Buffer + iphdrlen + tcph->doff*4 , (max - tcph->doff*4-iph->ihl*4) );
    fprintf(fp,"\n###########################################################");
}
 
void udppkt(unsigned char *Buffer , int max)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
     
    fprintf(fp,"\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,max);           
     
    fprintf(fp,"\nUDP Header\n");
    fprintf(fp,"   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(fp,"   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(fp,"   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(fp,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(fp,"\n");
    fprintf(fp,"IP Header\n");
    disp(Buffer , iphdrlen);
         
    fprintf(fp,"UDP Header\n");
    disp(Buffer+iphdrlen , sizeof udph);
         
    fprintf(fp,"Data Payload\n");  
    disp(Buffer + iphdrlen + sizeof udph ,( max - sizeof udph - iph->ihl * 4 ));
     
    fprintf(fp,"\n###########################################################");
}
 
void disp (unsigned char* data , int max)
{
     
    for(i=0 ; i < max ; i++)
    {
        if( i!=0 && i%16==0)   
        {
            fprintf(fp,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(fp,"%c",(unsigned char)data[j]); 
                 
                else fprintf(fp,"."); 
            }
            fprintf(fp,"\n");
        } 
         
        if(i%16==0) fprintf(fp,"   ");
            fprintf(fp," %02X",(unsigned int)data[i]);
                 
        if( i==max-1) 
        {
            for(j=0;j<15-i%16;j++) fprintf(fp,"   "); 
             
            fprintf(fp,"         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(fp,"%c",(unsigned char)data[j]);
                else fprintf(fp,".");
            }
            fprintf(fp,"\n");
        }
    }
}
