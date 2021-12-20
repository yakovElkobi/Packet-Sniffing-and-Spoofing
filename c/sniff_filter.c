#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "myheader.h"
#include <ctype.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  printf("\nget paket\n");
  int size_data = 0;
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("       To: %s\n", inet_ntoa(ip->iph_destip));    
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ipheader) + sizeof(struct ethheader));
    printf("       Source port: %d\n", ntohs(tcp->tcp_sport));   
    printf("       Destantion port: %d\n", ntohs(tcp->tcp_dport));  
    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            break;
        default:
            printf("   Protocol: others\n");
            break;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp and (src host 10.0.2.4 and dst host 10.0.2.5) or (src host 10.0.2.5 and dst host 10.0.2.4)";
  //char filter_exp[] = "tcp and dst portrange 10-100";
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