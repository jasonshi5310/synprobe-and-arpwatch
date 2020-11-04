# CSE 331 HW3
# part 2
# Minqi Shi

# import os
# import re

from scapy.all import *
import sys
from python_arptable import get_arp_table


global cache

def arp_checker(packet):
    if packet[ARP].op != 2:
        return
    elif packet[ARP].op == 2:
        global cache
        arp = packet[ARP]
        ip = arp.psrc
        hw = arp.hwsrc
        if cache.get(ip) != None and cache[ip] != hw:
            msg = ip+" changed from "+cache[ip]+" to "+hw
            print(msg)
        elif cache.get(ip) != None and cache[ip] == hw:
            pass
        else:
            cache.setdefault(ip, hw)
            print("A new IP "+ip+" with HW address "+hw+" is added")


def nonstop(packet):
    return 1==0

def main():
    global cache
    interface = 'eth0'
    argv = sys.argv
    l = get_if_list()
    if len(l) == 0:
        exit(0)
    if len(argv) != 1 and len(argv) != 3:
        exit(0)
    if len(argv) == 1:
        if interface in l:
            pass
        else:
            interface = l[0]
    if len(argv) == 3:
        if argv[1] == '-i':
            interface = argv[2]
            if l.index(interface) == -1:
                exit(0)
        if argv[1] != '-i':
            exit(0)
    # Used the following link to get the arp table
    # https://pypi.org/project/python_arptable/
    arp_table = get_arp_table()
    interface_dict = dict()
    for arp in arp_table:
        if l.index(arp['Device']) != -1:
            temp = dict({arp['IP address']:arp['HW address']})
            interface_dict.setdefault(arp['Device'], temp)
    cache = interface_dict[interface]
    sniff(iface=interface, filter='arp', prn=arp_checker, stop_filter=nonstop)


if __name__ == "__main__":
    main()
