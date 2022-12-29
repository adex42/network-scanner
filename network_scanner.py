#!/usr/bin/env python

import scapy.all as scapy
import optparse
def getarguments():
    parser = optparse.OptionParser()
    parser.add_option("-t",'--target',dest="target",help="The target network to be scanned")
    (options,arguments)=parser.parse_args()
    if not options.target:
        parser.error("[-] Please enter the target ip range to use , use --help for more help")
    return options

def print_list(list):
    for element in list:
        print(element["ip"]+ "\t\t"+element["mac"] )

def scan(ip):
    apr_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    apr_request_broadcast = broadcast/apr_request
    answered = scapy.srp(apr_request_broadcast , timeout = 1 , verbose = False)[0]
    clients_list= []
    print("IP\t\t\tMac Address\n-----------------------------------------")
    for ele in answered:
        client_dict = {"ip":ele[1].psrc,"mac":ele[1].hwsrc,}
        clients_list.append(client_dict)
    print_list(clients_list)

options = getarguments()
scan(options.target)
