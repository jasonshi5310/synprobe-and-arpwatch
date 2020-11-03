# CSE 331 HW3
# part 2
# Minqi Shi

# import os
# import re

from scapy.all import *
import sys


def main():
    interface = 'eth0'
    argv = sys.argv
    if len(argv) != 1 and len(argv) != 3:
        exit(1)
    if len(argv) == 3:
        if argv[1] != '-i':
            exit(1)
        else:
            interface = argv[2]
    arp = ''
    sniff(iface=interface, prn=arp, filter='arp')
    # sniff(prn=arp_monitor_callback, filter='arp', store =0)
    # This part is copied from stackoverflow
    # with os.popen('arp -a') as f:
    #     data = f.read()
    #     for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)',data):
    #         print(line)


if __name__ == "__main__":
    main()
