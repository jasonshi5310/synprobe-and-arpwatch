# CSE 331 hw3
# remember to include reference later!!

from scapy.all import *
import sys
import socket
from multiprocessing import Process
from itertools import count
import time


def scan(target, deport):
    # The following expressions are copyed from scapy reference
    # and the youtube video
    try:
        response = sr1(IP(dst=target)/TCP(dport=deport,flags='S'), timeout=1.14514, verbose=0)
        if response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
            # the port is open!
            print('open')
            pass
        else:
            while True:
                # just loop it!
                time.sleep(19.19)
    except AttributeError:
        time.sleep(19.19)


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
    # The following codes are inspired from creating a socket section
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # try:
    #     s.connect((target,deport))
    # except OSError:
    #     return ''
    # s.settimeout(1.14514)
    # msg = 'I hate this h******k so much; but I am not goind to say it :)'.encode()
    for i in range(3):
        packet = IP(dst=target)/TCP(dport=deport, flags='S')
        response = sr1(packet, timeout=1.14514)
        if response != None:
            return response[0:1024]
        else:
            continue
        # s.sendall(msg)
        # bytes_recd = 0
        # chunks = []
        # to_continue = False
        # while bytes_recd < 1024:
        #     chunk = b''
        #     try:
        #         chunk = s.recv(min(1024, 1024-bytes_recd))
        #     except socket.timeout:
        #         chunk = b''
        #     print(0)
        #     if chunk == b'':
        #         to_continue = True
        #         break
        #     chunks.append(chunk)
        #     bytes_recd += len(chunk)
        # if to_continue == True:
        #     continue
        # fingerprint = b''.join(chunks)
        # break
    if fingerprint == 'some unique fingerprint':
        fingerprint = 'Port:{}, 3 requests transmitted, 0 bytes received'
        fingerprint = fingerprint.format(deport)
    return fingerprint


def main():
    # print(sys.argv)
    argv = sys.argv
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
    # s = sr(IP(dst=target)/TCP(dport=ports,flags='S'))
    opened_dict = {}
    for i in ports:
        counter = count(0)
        pname = 'scan port ' + str(i)
        p = Process(target=scan, name=pname, args=(target,i,))
        p.start()
        p.join(timeout=3.16)
        if p.is_alive():
            # print('timeout',i)
            p.terminate()
            opened_dict.setdefault(i,'closed')
        else:
            opened_dict.setdefault(i,'open')
        # p.terminate()
        # ans, unans = sr(IP(dst=target)/TCP(dport=i,flags='S'))
        # print(ans)
        # if ans == []:
        #     print(i,'closed')
        #     continue
        # Add reference
        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('PORT STATUS FINGERPRINT')
    for i in ports:
        if opened_dict[i] != 'open':
            print(i,'closed')
        else:
            result = getFingerPrint(target,i)
            print(i, 'open', result)
        


if __name__ == "__main__":
    main()