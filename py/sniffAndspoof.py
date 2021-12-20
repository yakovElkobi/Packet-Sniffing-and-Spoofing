#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type==8:
        print("Original packet....")
        print("Source IP: ", pkt[IP].src)
        print("Destenation IP",pkt[IP].dst)

        ip = IP(src=pkt[IP].dst, dst = pkt[IP].src, ihl = pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip/icmp/data

        print("Spoofed packet....")
        print("Source IP: ",newpkt[IP].src)
        print("Destenation IP",newpkt[IP].dst)
        send(newpkt,verbose=0)

pkt = sniff(filter = 'icmp and src host 10.0.2.5' ,prn=spoof_pkt)

