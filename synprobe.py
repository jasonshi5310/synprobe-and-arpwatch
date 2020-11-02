# CSE 331 hw3
# remember to include reference later!!

from scapy.all import *
import sys
import time


opened_dict = {}

def scan(target, deport):
    # The following expressions are copyed from scapy reference
    # https://scapy.readthedocs.io/en/latest/usage.html#syn-scans
    # and the youtube video
    #https://www.youtube.com/watch?v=4Y-MR-Hec5Y
    global opened_dict
    try:
        response = sr1(IP(dst=target)/TCP(dport=deport,flags='S'), timeout=1.14514, verbose=0)
        if response!= None and response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
            # the port is open!
            opened_dict.setdefault(deport,'open')
        elif response!= None and response.haslayer(TCP) and response.getlayer(TCP).flags==0x4:
            opened_dict.setdefault(deport, 'closed')
        else:
            opened_dict.setdefault(deport, 'filtered')
    except AttributeError:
        pass


def my_hexdump(x, indent):
    """Build a tcpdump like hexadecimal view
    This function is altered version from the original hexdump in utils.py
    :param x: a Packet
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
            ports = toList(argv[2])
    target = argv[-1]
    conf.verb = 0
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
