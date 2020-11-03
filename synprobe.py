# CSE 331 hw3
# Minqi Shi

from scapy.all import *
import sys
import time
import ipaddress


opened_dict = {}

def scan(target, deport):
    # The following expressions are inspired from scapy reference
    # https://scapy.readthedocs.io/en/latest/usage.html#syn-scans
    # and the youtube video
    #https://www.youtube.com/watch?v=4Y-MR-Hec5Y
    # and thePacketGeek
    # https://thepacketgeek.com/scapy/building-network-tools/part-10/
    global opened_dict
    try:
        for i in range(3):
            response = sr1(IP(dst=target)/TCP(dport=deport,flags='S'), timeout=1.14514, verbose=0)
            if response == None:
                continue
            if response is not None and response.haslayer(TCP):
                # the port is open!
                if response.getlayer(TCP).flags==0x12:
                    opened_dict.setdefault(deport,'open')
                    break
                elif response.getlayer(TCP).flags==0x14:
                    opened_dict.setdefault(deport,'closed')
                    break
            # elif response!= None and response.haslayer(TCP) and response.getlayer(TCP).flags==0x14:
            #     opened_dict.setdefault(deport, 'closed')
            elif response is not None and response.haslayer(ICMP):
                if (int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    opened_dict.setdefault(deport, 'filtered')
                    break
            # else:
            #     opened_dict.setdefault(deport, 'filtered')
        opened_dict.setdefault(deport, 'filtered')
        # print(deport)
    except AttributeError:
        pass


def my_hexdump(x, indent):
    """Build a tcpdump like hexadecimal view
    This function is altered version from the original hexdump in utils.py
    :param x: a Packet
    :param indent: indentation
    """
    s = ""
    x = bytes_encode(x)
    x_len = len(x)
    i = 0
    while i < min(x_len, 1024):
        if i != 0:
            s+= indent
        s += "%04x  " % i
        for j in range(16):
            if i + j < x_len:
                s += "%02X " % orb(x[i + j])
            else:
                s += "   "
        s += " %s\n" % sane_color(x[i:i + 16])
        i += 16
    # remove trailing \n
    s = s[:-1] if s.endswith("\n") else s
    return s


def toList(s):
    if '-' in s:
        start = int(s.split('-')[0])
        end = int(s.split('-')[1])
        l = []
        for i in range(start,end+1):
            l.append(i)
        return l
    elif ',' in s:
        sl = s.split(',')
        l = []
        for i in sl:
            l.append(int(i))
        return l
    else:
        return [int(s)]


def getFingerPrint(target, deport):
    fingerprint = 'some unique fingerprint'
    # The following codes are inspired from youtube video
    # https://www.youtube.com/watch?v=4Y-MR-Hec5Y
    for i in range(3):
        packet = IP(dst=target)/TCP(dport=deport, flags='S')
        response = sr1(packet, timeout=1.114514)
        if response != None:
            indent = (4 + 2 + len(str(deport)))*' '
            return my_hexdump(response, indent)
        else:
            continue
    if fingerprint == 'some unique fingerprint':
        fingerprint = 'Port:{}, 3 requests transmitted, 0 bytes received'
        fingerprint = fingerprint.format(deport)
    return fingerprint


def main():
    argv = sys.argv
    global opened_dict
    if len(argv) != 2 and len(argv) != 4:
        exit(1)
    ports = [80,440,441,442,433]
    if len(argv) == 4:
        if argv[1] != '-p':
            exit(1)
        else:
            try:
                ports = toList(argv[2])
            except:
                exit(1)
    conf.verb = 0
    target = argv[-1]
    targets = []
    if target.find('/')!= -1:
        targets = ipaddress.ip_network(target)
        for host in targets.hosts():
            for j in ports:
                scan(host, j)
            print('PORT STATUS FINGERPRINT FOR:', host)
            for k in ports:
                if opened_dict[k] == 'closed':
                    print(k,'closed')
                elif opened_dict[k] == 'filtered':
                    print(k, 'filtered')
                elif opened_dict[k]== 'open':
                    result = getFingerPrint(host,k)
                    print(k, 'open', result)  
        # print(targets.hosts())
        exit(0)
    for i in ports:
        scan(target,i)
    print('PORT STATUS FINGERPRINT')
    for i in ports:
        if opened_dict[i] == 'closed':
            print(i,'closed')
        elif opened_dict[i] == 'filtered':
            print(i, 'filtered')
        elif opened_dict[i]== 'open':
            result = getFingerPrint(target,i)
            print(i, 'open', result)
        

if __name__ == "__main__":
    main()
