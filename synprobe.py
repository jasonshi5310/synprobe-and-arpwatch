# CSE 331 hw3
# remember to include reference later!!

from scapy.all import *
import sys
import socket
from multiprocessing import Process
from itertools import count


def scan(target, deport):
    # The following expressions are copyed from scapy reference
    ans, unans = sr(IP(dst=target)/TCP(dport=deport,flags='S'))
    # print(ans[0][1].fields_desc[5].names)
    # if "SA" in summary:
    #     print("Yes")


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
    fingerprint = 'some finger print'
    # The following codes are inspired from creating a socket section
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target,deport))
    msg = 'I hate this h******k so much; but I am not goind to say it :)'.encode()
    for i in range(3):
        s.sendall(msg)
        bytes_recd = 0
        chunks = []
        to_continue = False
        while bytes_recd < 1024:
            chunk = s.recv(min(1024, 1024-bytes_recd))
            print(0)
            if chuck == b'':
                to_continue = True
                break
            chunks.append(chunk)
            bytes_recd += len(chunk)
        if to_continue == True:
            continue
        fingerprint = b''.join(chunks)
        break
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
        p.join(timeout=3)
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
        if opened_dict[i] == 'closed':
            print(i,'closed', 'N/A')
        else:
            result = getFingerPrint(target,i)
            print(i, 'open', result)
        


if __name__ == "__main__":
    main()