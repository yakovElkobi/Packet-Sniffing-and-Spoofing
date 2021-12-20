#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "myheader.h"
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>



/**********************************************
 * Listing 12.9: Calculating Internet Checksum
 **********************************************/


unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}


/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;
    

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    printf("2 ");
    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));
    printf("4 \n");                 

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
    printf("   From %s\n", inet_ntoa(ip->iph_sourceip));
             printf("   to %s\n", inet_ntoa(ip->iph_destip));
    // Step 4: Send the packet out.
    if(sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info))<0){
             perror("error");
             exit(-1);
           }else{
             printf("------------------------------------\n");
             printf("   From %s\n", inet_ntoa(ip->iph_sourceip));
             printf("   to %s\n", inet_ntoa(ip->iph_destip));
             printf("------------------------------------\n");
           }
    
    close(sock);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  printf("\nget paket\n");
  int size_data = 0;
struct ipheader *ip = (struct ipheader *)
                        (packet + sizeof(struct ethheader)); 
spoof_reply(ip);
}

void spoof_reply(struct ipheader* ip)
{
    char data[IP_MAXPACKET] = "This is the spoofed packets!\n";
    unsigned int data_len = strlen(data) + 1;
    const char packet[IP_MAXPACKET];
    int ip_header_len = ip->iph_ihl * 4;

   // Step 1: Make a copy from the original packet
    memset((char*)packet, 0, 1500);
    memcpy(packet, ip, ip->iph_len);
    struct icmpheader *icmp = (struct icmpheader *)
                             (packet + ip_header_len);

 /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
   
   icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   //icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 //sizeof(struct icmpheader));
    //icmp->icmp_id = 18;
    //icmp->icmp_seq = 0;
    //icmp->icmp_code = 0;
   
   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *newip = (struct ipheader *) packet;
   //newip->iph_ver = 4;
   //newip->iph_ihl = 5;
   //newip->iph_ttl = 20;
   newip->iph_sourceip = ip->iph_destip;
   newip->iph_destip = ip->iph_sourceip;
   //newip->iph_protocol = IPPROTO_ICMP;
   //newip->iph_len = htons(sizeof(struct ipheader) +
                      // sizeof(struct icmpheader));
   

   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
   send_raw_ip_packet (newip);
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  //char filter_exp[] = "ip proto icmp";
  char filter_exp[] = "icmp and src host 10.0.2.5";
  //char filter_exp[] = "tcp and dst portrange 10-100";
  //char filter_exp[] = "ip proto icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}