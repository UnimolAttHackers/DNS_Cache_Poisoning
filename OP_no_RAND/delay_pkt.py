#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import argparse
import time


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print("Pkt drop") 
    #time.sleep(3)
    #packet.accept()
    packet.drop()    
try:  
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("Closing.....")
    
