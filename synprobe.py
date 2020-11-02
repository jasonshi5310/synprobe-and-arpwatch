# CSE 331 hw3
# remember to include reference later!!

from scapy.all import *
import sys
import socket
from multiprocessing import Process
from itertools import count


def scan(target, deport):
    ans, unans = sr(IP(dst=target)/TCP(dport=deport,flags='S'))
    print()

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




def main():
    print(sys.argv)
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
            print('timeout',i)
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
        


if __name__ == "__main__":
    main()