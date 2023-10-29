from scapy.all import *
import matplotlib.pyplot as plt
from sys import argv
from sys import exit
import numpy as np





""" Home Sniffer Montana v1.0

Call script : sudo python3 montana.py INTERFACE timetocapture
  
OSI LAYERS

(7) [APPLICATIONS] |HTTP/FTP/SSH/DNS|
(6) [PRESENTATION] |SSL/SSH/IMAP/FTP|
(5) [SESSION     ] |APIs / SOCKET   |
(4) [TRANSPORT   ] |TCP     /    UDP|
(3) [RESEAU      ] |IP / ICMP/ IPSec|
(2) [LIEN        ] |Ethernet / PPP  |
(1) [PHYSIQUE    ] |###UNUSED HERE##|

"""

interface = argv[1] ## ARGV[0] = script title 
tOut = int(argv[2])
filters =["udp or tcp or icmp or arp"]
udp = []
tcp = []
icmp = []
arp = []

def store_Packet(x):
    if x.haslayer(UDP):
        udp.append(x)
    if x.haslayer(TCP):
        tcp.append(x)
    if x.haslayer(ICMP):
        icmp.append(x)
    if x.haslayer(ARP):
        arp.append(x)

def total_Packets(udp,tcp,icmp,arp):
    return (len(udp)+len(tcp)+len(arp)+len(icmp))

def compute_Percentage(protocol=None,fs=1):
    return (len(protocol)/fs)

def pie_Plot(udp=udp,tcp=tcp,icmp=icmp,arp=arp):
    labels='udp','tcp','icmp','arp'
    sizes=[len(udp),len(tcp),len(icmp),len(arp)]
    plt.pie(sizes,labels=labels)
    plt.plot()

def list_Packets(protocol=None):
    if len(protocol) == 0:
        exit(ValueError)
    for i in range(len(protocol)):
        print("*** PACKET N° " + str(i) + "\n\r" )
        protocol[i].show()


print("*** Welcome to Montana *** \n\r")
selector=input("Do you want to sniff over interface "+argv[1]+" during "+argv[2]+" seconds ? [y/N]")

if selector=='y' or selector=='Y':
    print("Let's sniff !!!!\r\n")
    sniff(filter=filters[0],count=0,prn=lambda x:store_Packet(x),iface=interface,timeout=tOut)
    fullScale=total_Packets(udp,tcp,icmp,arp)
    # Tests & Debug
    print("Total sniffed packets ="+str(fullScale)+"\n\r")
    print(str(100*compute_Percentage(udp,fullScale))+"% \of UDP \r\n")
    print(str(100*compute_Percentage(tcp,fullScale))+"% \of TCP \r\n")
    print(str(100*compute_Percentage(icmp,fullScale))+"% \of ICMP \r\n")
    print(str(100*compute_Percentage(arp,fullScale))+"% \of ARP \r\n")

    if argv[3]=="-list":
        if argv[4] =="--udp":
            list_Packets(udp)
        if argv[4] =="--tcp":
            list_Packets(tcp)
        if argv[4] =="--arp":
            list_Packets(arp)
        if argv[4] =="--icmp":
            list_Packets(icmp)
        if argv[4] =="--all":
            list_Packets(udp)
            list_Packets(tcp)
            list_Packets(arp)
            list_Packets(icmp)
else:
    print("Thanks for using ! Goodbye ! \n\r")

