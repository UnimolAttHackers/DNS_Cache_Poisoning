#!usr/bin/python3
from scapy.all import * 
f = open("ip_req.bin","wb")
Qdsec = DNSQR(qname="aaaaa.example.com")
DNSpkt = DNS(id=0xAAAA, qr=0, qdcount = 1, ancount = 0, nscount = 0, arcount = 0, qd = Qdsec)
IPpkt = IP(dst = "10.10.10.4", src  = "10.10.10.15")
UDPpkt = UDP(dport = 53, sport = 33333, chksum = 0)
request = IPpkt/UDPpkt/DNSpkt
f.write(bytes(request))
f.close 
