# BPF Simple Packet Tracer with DNS Interruption

## Description

This is a simple packet tracer, written in Objective-C for macOS environment.<br>
It utilizes the BPF technology, and uses BPF pseudo-device as the sniffer.<br>
By default, it will also try to send a NULL answer to DNS requests,<br>
in order to perform some tiny DOS incidents.

## Getting Started

### Compiling and Running

1. Compile with the Foundation framework
```
gcc -framework Foundation main.m -o main
```
2. Run as root
```
sudo ./main
```
3. Watch packets fly

### Run Example
 ```
BPF bytes read: 93
BPF time stamp: 1695255442:425535
BPF captured size: 127
BPF data size: 127
BPF header size: 18
Ethernet source MAC address: 0:e:11:6:c9:aa
Ethernet detination MAC address: 2:0:3b:0:0:fb
Source IP address: 123.45.67.89
Destination IP address: 98.76.54.132
IP Frame
IP header size: 20
IP version: 4
IP protocol: 17
IP ttl: 255
UDP source port number: 5353
UDP destination port number: 5353
UDP length: 93
UDP checksum: 57666
UDP payload data:
00000000000400000000009999999963          ............._sp 
616e6e6599999999637005999999996c          linter._tcp.loca 
00000c00010459999999909999999901          l....._abc...... 
085f7078888e7465799999999c00010f          ._shreder....... 
5f706468888999999993747299999999          _cjf-sagesleakm. 
15000c00010000000000000000                   ............. 


BPF bytes read: 44
BPF time stamp: 1695255464:424551
BPF captured size: 78
BPF data size: 78
BPF header size: 18
Ethernet source MAC address: 0:a:30:55:b5:fb
Ethernet detination MAC address: 0:58:56:dd:39:5e
Source IP address: 123.45.67.89
Destination IP address: 98.76.54.132
IP Frame
IP header size: 20
IP version: 4
IP protocol: 6
IP ttl: 64
TCP source port number: 62666
TCP destination port number: 443
TCP Sequence Number: 251152111
TCP Acknowledge Number: 1770543111
TCP Header Length: 5
TCP CWR Flag : 0
TCP ECN Flag : 0
TCP Urgent Flag : 0
TCP Acknowledgement Flag : 1
TCP Push Flag : 1
TCP Reset Flag : 0
TCP Synchronise Flag : 0
TCP Finish Flag : 0
TCP Window : 65535
TCP Checksum : 49999
TCP Urgent Pointer : 0
TCP payload data:
6989999a9999ffffc307000017030300          i.AAA........... 
138999932b019999abc999990ae70176          ..+=#.t........r 
043999980000000000000000                      .3Gx........
```
