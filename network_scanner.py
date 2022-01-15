#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def get_input():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP range.")
    options = parser.parse_args()
    return options



def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]

    # print("IP\t\t\tMAC Adress\n-----------------------------------")
    clients_list = []
    print("\n-------------------------------------")
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        # print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return clients_list

def print_result(results_list):
    print("IP Address \t\tMAC Address\n-------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_input()
scan_result = scan(options.target)
print_result(scan_result) 
