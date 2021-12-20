#!/usr/bin/env python3
from scapy.all import *

a = IP()

a.dst = '34.96.118.58'
for i in range(1,14):
    a.ttl = i
    b =ICMP()
    send(a/b)
