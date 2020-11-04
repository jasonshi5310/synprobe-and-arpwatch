# CSE 331 hw3
# Minqi Shi

from scapy.all import *
import sys
import time
import ipaddress


opened_dict = {}

def scan(target, deport):
    # This is not an original function!!!!
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
                    opened_dict.setdefault(deport,('open',response))
                    break
                elif response.getlayer(TCP).flags==0x14:
                    opened_dict.setdefault(deport,('closed',1))
                    break
            # elif response!= None and response.haslayer(TCP) and response.getlayer(TCP).flags==0x14:
            #     opened_dict.setdefault(deport, 'closed')
            elif response is not None and response.haslayer(ICMP):
                if (int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    opened_dict.setdefault(deport, ('filtered',1))
                    break
            # else:
            #     opened_dict.setdefault(deport, 'filtered')
        opened_dict.setdefault(deport, ('filtered',1))
        # print(deport)
    except AttributeError:
        pass
    except:
        pass


def indent_hexdump(x, indent):
    """Build a tcpdump like hexadecimal view
    This is not an original function!!!!
    This function is altered version from the original hexdump in utils.py
    :param x: a Packet
    :param indent: indentation
    """
    s = ""
    # x = bytes_encode(x)
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


def getFingerPrint(target, t):
    # This is not an original function!!!
    # The following codes are inspired from youtube video
    # https://www.youtube.com/watch?v=4Y-MR-Hec5Y
    # and stackoverflow
    # https://stackoverflow.com/questions/4750793/python-scapy-or-the-like-how-can-i-create-an-http-get-request-at-the-packet-leve
    fingerprint = 'some unique fingerprint'
    deport, res = t
    for i in range(3):
        if res == None or res[IP].proto!=6:
            break
        ack_no = res[TCP].seq+1
        p = IP(dst=target)/TCP(sport=res[TCP].dport ,dport=deport, ack=ack_no, seq=res[TCP].ack, flags="A")
        filter_string = ''#'src net '+target+' and tcp src port '+str(deport)
        send(p,verbose=0)
        response = sniff(filter=filter_string, timeout=1.114514)
        for j in range(3):
            if len(response)!=0:
                break
            else:
                # print('one more try')
                header = 'GET / HTTP/1.1\r\nHost: '+target+'\r\n\r\n'
                p = IP(dst=target)/TCP(sport=res[TCP].dport ,dport=deport, ack=ack_no, seq=res[TCP].ack, flags="PA")/header
                send(p, verbose=0)
                response=sniff(filter=filter_string,timeout=2.14**(j+1))
        if len(response)==0:
            break
        else:
            indent = (4 + 2 + len(str(deport)))*' '
            fp = b''
            for i in response:
                fp += (bytes(i[IP]))
            return indent_hexdump(fp, indent)
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
            opened_dict={}
            for j in ports:
                scan(str(host), j)
            print('PORT STATUS FINGERPRINT FOR:', host)
            for k in ports:
                if opened_dict[k][0] == 'closed':
                    print(k,'closed')
                elif opened_dict[k][0] == 'filtered':
                    print(k, 'filtered')
                elif opened_dict[k][0]== 'open':
                    result = getFingerPrint(str(host),(j, opened_dict[k][1]))
                    print(k, 'open', result)
        exit(0)
    for i in ports:
        scan(target,i)
    print('PORT STATUS FINGERPRINT')
    for i in ports:
        if opened_dict[i][0] == 'closed':
            print(i,'closed')
        elif opened_dict[i][0] == 'filtered':
            print(i, 'filtered')
        elif opened_dict[i][0]== 'open':
            result = getFingerPrint(target,(i,opened_dict[i][1]))
            print(i, 'open', result)
        

if __name__ == "__main__":
    main()
