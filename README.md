# cse331hw3 README

Task 1:
Required command:
# You may need to do these commands before running
sudo apt update
sudo apt install python3-pip
# The following must be down before running the code
# This is for installing scapy
sudo pip3 install scapy --pre scapy[basic]

To run the code, please direct yourself into the correct folder and do:
sudo python3 synprobe.py [-p port_range] target

For case 1, do:
sudo python3 synprobe.py 172.217.6.206
# This is for port 80 440 441 442 443
PORT STATUS FINGERPRINT
80 open Port:80, 3 requests transmitted, 0 bytes received
440 filtered
441 filtered
442 filtered
443 open 0000  45 00 00 47 C9 E7 40 00 40 11 A4 06 0A 00 02 0F  E..G..@.@.......
         0010  C0 A8 00 01 C5 5F 00 35 00 33 CC FC B6 09 01 00  ....._.5.3......
         0020  00 01 00 00 00 00 00 00 06 76 6F 72 74 65 78 04  .........vortex.
         0030  64 61 74 61 09 6D 69 63 72 6F 73 6F 66 74 03 63  data.microsoft.c
         0040  6F 6D 00 00 01 00 01 45 00 00 47 C9 E8 40 00 40  om.....E..G..@.@
         0050  11 A4 05 0A 00 02 0F C0 A8 00 01 C5 5F 00 35 00  ............_.5.
         0060  33 CC FC FC 0A 01 00 00 01 00 00 00 00 00 00 06  3...............
         0070  76 6F 72 74 65 78 04 64 61 74 61 09 6D 69 63 72  vortex.data.micr
         0080  6F 73 6F 66 74 03 63 6F 6D 00 00 1C 00 01 45 00  osoft.com.....E.
         0090  00 8A 63 CF 00 00 40 11 49 DC C0 A8 00 01 0A 00  ..c...@.I.......
         00a0  02 0F 00 35 C5 5F 00 76 BE B1 B6 09 81 80 00 01  ...5._.v........
         00b0  00 02 00 00 00 00 06 76 6F 72 74 65 78 04 64 61  .......vortex.da
         00c0  74 61 09 6D 69 63 72 6F 73 6F 66 74 03 63 6F 6D  ta.microsoft.com
         00d0  00 00 01 00 01 C0 0C 00 05 00 01 00 00 07 42 00  ..............B.
         00e0  27 06 61 73 69 6D 6F 76 06 76 6F 72 74 65 78 04  '.asimov.vortex.
         00f0  64 61 74 61 0E 74 72 61 66 66 69 63 6D 61 6E 61  data.trafficmana
         0100  67 65 72 03 6E 65 74 00 C0 37 00 01 00 01 00 00  ger.net..7......
         0110  00 20 00 04 41 37 2C 6D 45 00 00 C9 63 D0 00 00  . ..A7,mE...c...
         0120  40 11 49 9C C0 A8 00 01 0A 00 02 0F 00 35 C5 5F  @.I..........5._
         0130  00 B5 08 78 FC 0A 81 80 00 01 00 02 00 01 00 00  ...x............
         0140  06 76 6F 72 74 65 78 04 64 61 74 61 09 6D 69 63  .vortex.data.mic
         0150  72 6F 73 6F 66 74 03 63 6F 6D 00 00 1C 00 01 C0  rosoft.com......
         0160  0C 00 05 00 01 00 00 05 16 00 27 06 61 73 69 6D  ..........'.asim
         0170  6F 76 06 76 6F 72 74 65 78 04 64 61 74 61 0E 74  ov.vortex.data.t
         0180  72 61 66 66 69 63 6D 61 6E 61 67 65 72 03 6E 65  rafficmanager.ne
         0190  74 00 C0 37 00 05 00 01 00 00 00 3C 00 09 06 67  t..7.......<...g
         01a0  6C 6F 62 61 6C C0 3E C0 4A 00 06 00 01 00 00 00  lobal.>.J.......
         01b0  04 00 2E 03 74 6D 31 06 64 6E 73 2D 74 6D C0 22  ....tm1.dns-tm."
         01c0  0A 68 6F 73 74 6D 61 73 74 65 72 C0 4A 77 64 96  .hostmaster.Jwd.
         01d0  60 00 00 03 84 00 00 01 2C 00 24 EA 00 00 00 00  `.......,.$.....
         01e0  1E 45 00 00 3C 3F 81 40 00 40 06 81 88 0A 00 02  .E..<?.@.@......
         01f0  0F 41 37 2C 6D B7 DE 01 BB 22 B8 7A 11 00 00 00  .A7,m....".z....
         0200  00 A0 02 FA F0 79 E1 00 00 02 04 05 B4 04 02 08  .....y..........
         0210  0A 3C B6 AB E6 00 00 00 00 01 03 03 07 45 00 00  .<...........E..
         0220  2C 63 D1 00 00 40 06 9D 48 41 37 2C 6D 0A 00 02  ,c...@..HA7,m...
         0230  0F 01 BB B7 DE 2D 27 92 01 22 B8 7A 12 60 12 FF  .....-'..".z.`..
         0240  FF 08 D7 00 00 02 04 05 B4 00 00 45 00 00 28 3F  ...........E..(?
         0250  82 40 00 40 06 81 9B 0A 00 02 0F 41 37 2C 6D B7  .@.@.......A7,m.
         0260  DE 01 BB 22 B8 7A 12 2D 27 92 02 50 10 FA F0 79  ...".z.-'..P...y
         0270  CD 00 00 45 00 02 2D 3F 83 40 00 40 06 7F 95 0A  ...E..-?.@.@....
         0280  00 02 0F 41 37 2C 6D B7 DE 01 BB 22 B8 7A 12 2D  ...A7,m....".z.-
         0290  27 92 02 50 18 FA F0 7B D2 00 00 16 03 01 02 00  '..P...{........
         02a0  01 00 01 FC 03 03 22 4D BB 36 33 EA CE 42 D6 CA  ......"M.63..B..
         02b0  EB 40 81 E4 D0 FF 44 B6 8D 14 82 79 3A D6 C8 DE  .@....D....y:...
         02c0  49 36 C0 97 FF F4 20 78 10 00 00 81 FB 36 44 88  I6.... x.....6D.
         02d0  C3 54 21 DF D6 BE FC 54 7E 6C 8E 51 EF 4A D8 29  .T!....T~l.Q.J.)
         02e0  36 CB 4E 2F AF E9 C6 00 24 13 03 13 01 13 02 C0  6.N/....$.......
         02f0  2F C0 2B C0 30 C0 2C CC A9 CC A8 C0 09 C0 13 C0  /.+.0.,.........
         0300  0A C0 14 00 9C 00 9D 00 2F 00 35 00 0A 01 00 01  ......../.5.....
         0310  8F 00 00 00 1E 00 1C 00 00 19 76 6F 72 74 65 78  ..........vortex
         0320  2E 64 61 74 61 2E 6D 69 63 72 6F 73 6F 66 74 2E  .data.microsoft.
         0330  63 6F 6D 00 17 00 00 FF 01 00 01 00 00 0A 00 08  com.............
         0340  00 06 00 1D 00 17 00 18 00 0B 00 02 01 00 00 23  ...............#
         0350  00 00 00 0D 00 14 00 12 04 03 08 04 04 01 05 03  ................
         0360  08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24  ...........3.&.$
         0370  00 1D 00 20 A0 C9 75 D5 E5 29 CA D7 5C 58 0F E9  ... ..u..)..\X..
         0380  21 1F 8F D4 FC E6 85 CC 0E 71 CD 9F 6D 1F 22 AE  !........q..m.".
         0390  27 8D 48 4B 00 2D 00 02 01 01 00 2B 00 05 04 03  '.HK.-.....+....
         03a0  04 03 03 00 15 00 F9 00 00 00 00 00 00 00 00 00  ................
         03b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
         03c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
         03d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
         03e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
         03f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................


Case 2 (with -p):
sudo python3 synprobe.py -p 78-80 172.217.6.206

Output for case 2:
PORT STATUS FINGERPRINT
78 filtered
79 filtered
80 open 0000  45 00 00 47 1A 45 40 00 40 11 53 A9 0A 00 02 0F  E..G.E@.@.S.....
        0010  C0 A8 00 01 AE 42 00 35 00 33 CC FC 9D 88 01 00  .....B.5.3......
        0020  00 01 00 00 00 00 00 00 06 76 6F 72 74 65 78 04  .........vortex.
        0030  64 61 74 61 09 6D 69 63 72 6F 73 6F 66 74 03 63  data.microsoft.c
        0040  6F 6D 00 00 01 00 01 45 00 00 47 1A 46 40 00 40  om.....E..G.F@.@
        0050  11 53 A8 0A 00 02 0F C0 A8 00 01 AE 42 00 35 00  .S..........B.5.
        0060  33 CC FC 61 73 01 00 00 01 00 00 00 00 00 00 06  3..as...........
        0070  76 6F 72 74 65 78 04 64 61 74 61 09 6D 69 63 72  vortex.data.micr
        0080  6F 73 6F 66 74 03 63 6F 6D 00 00 1C 00 01 45 00  osoft.com.....E.
        0090  00 8A 64 A1 00 00 40 11 49 0A C0 A8 00 01 0A 00  ..d...@.I.......
        00a0  02 0F 00 35 AE 42 00 76 3B 3E 9D 88 81 80 00 01  ...5.B.v;>......
        00b0  00 02 00 00 00 00 06 76 6F 72 74 65 78 04 64 61  .......vortex.da
        00c0  74 61 09 6D 69 63 72 6F 73 6F 66 74 03 63 6F 6D  ta.microsoft.com
        00d0  00 00 01 00 01 C0 0C 00 05 00 01 00 00 03 F5 00  ................
        00e0  27 06 61 73 69 6D 6F 76 06 76 6F 72 74 65 78 04  '.asimov.vortex.
        00f0  64 61 74 61 0E 74 72 61 66 66 69 63 6D 61 6E 61  data.trafficmana
        0100  67 65 72 03 6E 65 74 00 C0 37 00 01 00 01 00 00  ger.net..7......
        0110  00 35 00 04 41 37 2C 6D 45 00 00 C9 64 A2 00 00  .5..A7,mE...d...
        0120  40 11 48 CA C0 A8 00 01 0A 00 02 0F 00 35 AE 42  @.H..........5.B
        0130  00 B5 AA 2B 61 73 81 80 00 01 00 02 00 01 00 00  ...+as..........
        0140  06 76 6F 72 74 65 78 04 64 61 74 61 09 6D 69 63  .vortex.data.mic
        0150  72 6F 73 6F 66 74 03 63 6F 6D 00 00 1C 00 01 C0  rosoft.com......
        0160  0C 00 05 00 01 00 00 06 20 00 27 06 61 73 69 6D  ........ .'.asim
        0170  6F 76 06 76 6F 72 74 65 78 04 64 61 74 61 0E 74  ov.vortex.data.t
        0180  72 61 66 66 69 63 6D 61 6E 61 67 65 72 03 6E 65  rafficmanager.ne
        0190  74 00 C0 37 00 05 00 01 00 00 00 3C 00 09 06 67  t..7.......<...g
        01a0  6C 6F 62 61 6C C0 3E C0 4A 00 06 00 01 00 00 00  lobal.>.J.......
        01b0  0A 00 2E 03 74 6D 31 06 64 6E 73 2D 74 6D C0 22  ....tm1.dns-tm."
        01c0  0A 68 6F 73 74 6D 61 73 74 65 72 C0 4A 77 64 96  .hostmaster.Jwd.
        01d0  60 00 00 03 84 00 00 01 2C 00 24 EA 00 00 00 00  `.......,.$.....
        01e0  1E 45 00 00 3C 37 90 40 00 40 06 89 79 0A 00 02  .E..<7.@.@..y...
        01f0  0F 41 37 2C 6D B7 F8 01 BB 50 5D E6 50 00 00 00  .A7,m....P].P...
        0200  00 A0 02 FA F0 79 E1 00 00 02 04 05 B4 04 02 08  .....y..........
        0210  0A 3C BB 18 BC 00 00 00 00 01 03 03 07 45 00 00  .<...........E..
        0220  2C 64 A3 00 00 40 06 9C 76 41 37 2C 6D 0A 00 02  ,d...@..vA7,m...
        0230  0F 01 BB B7 F8 2E 6B CA 01 50 5D E6 51 60 12 FF  ......k..P].Q`..
        0240  FF 35 94 00 00 02 04 05 B4 00 00 45 00 00 28 37  .5.........E..(7
        0250  91 40 00 40 06 89 8C 0A 00 02 0F 41 37 2C 6D B7  .@.@.......A7,m.
        0260  F8 01 BB 50 5D E6 51 2E 6B CA 02 50 10 FA F0 79  ...P].Q.k..P...y
        0270  CD 00 00 45 00 02 2D 37 92 40 00 40 06 87 86 0A  ...E..-7.@.@....
        0280  00 02 0F 41 37 2C 6D B7 F8 01 BB 50 5D E6 51 2E  ...A7,m....P].Q.
        0290  6B CA 02 50 18 FA F0 7B D2 00 00 16 03 01 02 00  k..P...{........
        02a0  01 00 01 FC 03 03 B6 37 62 B5 0C F3 B9 42 1A 65  .......7b....B.e
        02b0  F3 55 BD 7B DE 5D 1A A1 F7 23 7E DA 66 64 B2 9D  .U.{.]...#~.fd..
        02c0  C3 FD 3B 49 12 B7 20 A7 04 00 00 C5 97 C4 D4 A3  ..;I.. .........
        02d0  54 D2 3F 69 75 DC BA 9B CD D6 B0 AD B7 87 34 59  T.?iu.........4Y
        02e0  9A 85 9C 28 90 2B 66 00 24 13 03 13 01 13 02 C0  ...(.+f.$.......
        02f0  2F C0 2B C0 30 C0 2C CC A9 CC A8 C0 09 C0 13 C0  /.+.0.,.........
        0300  0A C0 14 00 9C 00 9D 00 2F 00 35 00 0A 01 00 01  ......../.5.....
        0310  8F 00 00 00 1E 00 1C 00 00 19 76 6F 72 74 65 78  ..........vortex
        0320  2E 64 61 74 61 2E 6D 69 63 72 6F 73 6F 66 74 2E  .data.microsoft.
        0330  63 6F 6D 00 17 00 00 FF 01 00 01 00 00 0A 00 08  com.............
        0340  00 06 00 1D 00 17 00 18 00 0B 00 02 01 00 00 23  ...............#
        0350  00 00 00 0D 00 14 00 12 04 03 08 04 04 01 05 03  ................
        0360  08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24  ...........3.&.$
        0370  00 1D 00 20 AC ED 84 C2 F7 9D 30 ED 62 54 9B D0  ... ......0.bT..
        0380  F3 7B 62 53 5F D7 A1 DA F3 76 24 C2 F6 DC 3C 26  .{bS_....v$...<&
        0390  89 2E 7A 16 00 2D 00 02 01 01 00 2B 00 05 04 03  ..z..-.....+....
        03a0  04 03 03 00 15 00 F9 00 00 00 00 00 00 00 00 00  ................
        03b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
        03c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
        03d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
        03e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
        03f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

Case 3 for subnet:
sudo python3 synprobe.py -p 80 192.168.0.0/31

Output for case 3:
PORT STATUS FINGERPRINT FOR: 192.168.0.0
80 filtered
PORT STATUS FINGERPRINT FOR: 192.168.0.1
80 open Port:80, 3 requests transmitted, 0 bytes received



Task 2:
Required command:
# You may need to do these commands before running
sudo apt update
sudo apt install python3-pip
# The following must be done before running
# These are for installing python_arptable and dsniff
sudo pip3 install python_arptable 
sudo apt-get install dsniff

To run the code, please direct yourself into the correct folder and do:
sudo python3 arpwatch.py [-i interface]

Then open up another terminal,

For case 1:
In the new terminal, do:
sudo sysctl -w net.ipv4.ip_forward=1
sudo -s arpspoof -i eth0 10.0.2.2
# This is my original grand truth cache
# {'10.0.2.2': '52:54:00:12:35:02'}
Outoup of case 1:

In the old terminal:
10.0.2.2 changed from 52:54:00:12:35:02 to 08:00:27:5c:65:26
10.0.2.2 changed from 52:54:00:12:35:02 to 08:00:27:5c:65:26
10.0.2.2 changed from 52:54:00:12:35:02 to 08:00:27:5c:65:26

In the new terminal:
8:0:27:5c:65:26 ff:ff:ff:ff:ff:ff 0806 42: arp reply 10.0.2.2 is-at 8:0:27:5c:65:26
8:0:27:5c:65:26 ff:ff:ff:ff:ff:ff 0806 42: arp reply 10.0.2.2 is-at 8:0:27:5c:65:26
8:0:27:5c:65:26 ff:ff:ff:ff:ff:ff 0806 42: arp reply 10.0.2.2 is-at 8:0:27:5c:65:26


For case 2:
In the new terminal, do:
sudo sysctl -w net.ipv4.ip_forward=1
sudo -s arpspoof -i eth0 10.0.2.21
# This is my original grand truth cache
# {'10.0.2.2': '52:54:00:12:35:02'}
Output of case 2:

In the old terminal:
A new IP 10.0.2.21 with HW address 08:00:27:5c:65:26 is added
A new IP 10.0.2.21 with HW address 08:00:27:5c:65:26 is added
A new IP 10.0.2.21 with HW address 08:00:27:5c:65:26 is added

In the new terminal:
8:0:27:5c:65:26 ff:ff:ff:ff:ff:ff 0806 42: arp reply 10.0.2.21 is-at 8:0:27:5c:65:26
8:0:27:5c:65:26 ff:ff:ff:ff:ff:ff 0806 42: arp reply 10.0.2.21 is-at 8:0:27:5c:65:26
8:0:27:5c:65:26 ff:ff:ff:ff:ff:ff 0806 42: arp reply 10.0.2.21 is-at 8:0:27:5c:65:26


