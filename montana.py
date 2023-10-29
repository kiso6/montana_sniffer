from scapy.all import *
import matplotlib.pyplot as plt
from sys import argv
from sys import exit
import numpy as np





""" Home Sniffer Montana v1.0

Call script : sudo python3 montana.py INTERFACE timetocapture [-nstat] -list --PROTOCOL
  
OSI LAYERS

(7) [APPLICATIONS] |HTTP/FTP/SSH/DNS|
(6) [PRESENTATION] |SSL/SSH/IMAP/FTP|
(5) [SESSION     ] |APIs / SOCKET   |
(4) [TRANSPORT   ] |TCP     /    UDP| ---> Operate
(3) [NETWORK     ] |IP / ICMP/ IPSec| ---> Operate
(2) [LINK        ] |Ethernet / PPP  |
(1) [PHYSICAL    ] |###UNUSED HERE##|

"""

print(r""" __  __  ____  _   _ _______       _   _          
    |  \/  |/ __ \| \ | |__   __|/\   | \ | |   /\    
    | \  / | |  | |  \| |  | |  /  \  |  \| |  /  \   
    | |\/| | |  | | . ` |  | | / /\ \ | . ` | / /\ \  
    | |  | | |__| | |\  |  | |/ ____ \| |\  |/ ____ \ 
    |_|  |_|\____/|_| \_|  |_/_/    \_\_| \_/_/    \_\ \r\n""")

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

def display_Net_Stats(udp=None,tcp=None,arp=None,icmp=None):
    fullScale=total_Packets(udp,tcp,icmp,arp)
    print("Total sniffed packets ="+str(fullScale)+"\r\n")
    print(str(100*compute_Percentage(udp,fullScale))+"% \of UDP \r\n")
    print(str(100*compute_Percentage(tcp,fullScale))+"% \of TCP \r\n")
    print(str(100*compute_Percentage(icmp,fullScale))+"% \of ICMP \r\n")
    print(str(100*compute_Percentage(arp,fullScale))+"% \of ARP \r\n")

def list_Packets(protocol=None):
    if len(protocol) == 0:
        exit(ValueError)
    for i in range(len(protocol)):
        print("*** PACKET N° " + str(i) + "\r\n" )
        protocol[i].show()


print("*** Welcome to Montana *** \r\n")
selector=input("Do you want to sniff over interface "+argv[1]+" during "+argv[2]+" seconds ? [y/N]")

if selector=='y' or selector=='Y':
    print("Let's sniff !!!!\r\n")
    sniff(filter=filters[0],count=0,prn=lambda x:store_Packet(x),iface=interface,timeout=tOut)

    if argv[3]=="-nstat":
        display_Net_Stats(udp,tcp,arp,icmp)
    else:
        print("** No stats \r\n")

    if argv[4]=="-list":
        if argv[5] =="--udp":
            list_Packets(udp)
        if argv[5] =="--tcp":
            list_Packets(tcp)
        if argv[5] =="--arp":
            list_Packets(arp)
        if argv[5] =="--icmp":
            list_Packets(icmp)
        if argv[5] =="--all":
            list_Packets(udp)
            list_Packets(tcp)
            list_Packets(arp)
            list_Packets(icmp)
        if argv[5] == "--no":
            print("No list \r\n")

else:
    print("Wtf bro ?\r\n")

print("Thanks for using ! Goodbye ! \r\n")

