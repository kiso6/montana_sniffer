#!/usr/bin/env python3 

from scapy.all import *
import matplotlib.pyplot as plt
from sys import argv
from sys import exit
import numpy as np
from pathlib import Path
import os
import argparse

parser=argparse.ArgumentParser(prog="montana",
                               description="Montana is a command line sniffer based on Scapy",
                               epilog="Open Source, made with love by kiso6")

parser.add_argument("-i","--interface",help="Select the interface to sniff on")
parser.add_argument("-t","--timeout",help="Set the length of the sniffing session")
parser.add_argument("-f","--filter",help="Configure the filter applied to the sniffer")
parser.add_argument("-nstat","--netstat",help="Generates statistics")
parser.add_argument("-l","--list",help="Lists the packets captured (highly precise description)")
parser.add_argument("-r","--reverse",help="Launch a dig over the source ip addresses")
parser.add_argument("-of","--output",help="Store the captured packets in output file")


#./montana.py -i wlan0 -t 10 -f udp -nstat -l all -of ./text
args=parser.parse_args()



""" Home Sniffer Montana v1.0

 
OSI LAYERS

(7) [APPLICATIONS] |HTTP/FTP/SSH/DNS| ---> ***NEW : operate reverse DNS to match IP to DN ***
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
          |_|  |_|\____/|_| \_|  |_/_/    \_\_| \_/_/    \_\ """)

interface = args.interface #argv[1] ## ARGV[0] = script title 
tOut = int(args.timeout)#int(argv[2])
filters =["udp or tcp or icmp or arp",
          "udp","tcp","icmp","arp"]
udp = []
tcp = []
icmp = []
arp = []

def reverse_IP(protocol=None):
    for i in range(len(protocol)):
        pqt=protocol[i]
        print("Domain name for pqt n°"+str(i)+":")
        print(pqt)
        if (pqt.haslayer(IP)):
            os.system("dig -x "+str(pqt[IP].src)+" +short")
        elif (pqt.haslayer(IPv6)):
            os.system("dig -x "+str(pqt[IPv6].src)+" +short")
        else:
            print("No IP layer for pqt n°"+str(i))

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
    if (fs !=0):
        return (len(protocol)/fs)
    else:
        print("No packets captured.\r\n")

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
        print("!!! Nothing to list \r\n")
        exit(-1)
    for i in range(len(protocol)):
        print("*** PACKET N° " + str(i) + "\r\n" )
        protocol[i].show()

def output_Sniff(protocol=None,output=None):
    if len(protocol) == 0:
        print("!!! Nothing to write in log file\r\n")
        exit(-1)
    for i in range(len(protocol)):
        output.write("*** PACKET N° " + str(i) + "\r\n" )
        output.write(str(protocol[i])+"\r\n")


print("*** Welcome to Montana *** \r\n")
selector=input("Do you want to sniff over interface "+args.interface +" during "+args.timeout+" seconds ? [y/N]")

if selector=='y' or selector=='Y':
    print("Let's sniff !!!!\r\n")
    match args.filter:#argv[3]
        case "all":
            sniff(filter=filters[0],count=0,prn=lambda x:store_Packet(x),iface=interface,timeout=tOut)
        case "udp":
            sniff(filter=filters[1],count=0,prn=lambda x:store_Packet(x),iface=interface,timeout=tOut)
        case "tcp":
            sniff(filter=filters[2],count=0,prn=lambda x:store_Packet(x),iface=interface,timeout=tOut)
        case "icmp":
            sniff(filter=filters[3],count=0,prn=lambda x:store_Packet(x),iface=interface,timeout=tOut)
        case "arp":
            sniff(filter=filters[4],count=0,prn=lambda x:store_Packet(x),iface=interface,timeout=tOut)
        case other:
            print("No filter specified, exiting.\r\n")
            exit(-1)


    if args.netstat=="yes":
        display_Net_Stats(udp,tcp,arp,icmp)
    else:
        print("** No stats \r\n")

    match args.list: 
        case "udp":
            list_Packets(udp)
        case "tcp":
            list_Packets(tcp)
        case "arp":
            list_Packets(arp)
        case "icmp":
            list_Packets(icmp)
        case "all":
            list_Packets(udp)
            list_Packets(tcp)
            list_Packets(arp)
            list_Packets(icmp)
        case other:
            print("No list \r\n")
    
    match(args.reverse):
        case "tcp":
            reverse_IP(tcp)
        case "udp":
            reverse_IP(udp) ## Possibly a non sense
        case "icmp":
            reverse_IP(icmp)
        case "all":
            print("Reversed tcp requests :\r\n")
            reverse_IP(tcp)
            print("Reversed udp requests :\r\n")
            reverse_IP(udp)
        case others:
            print("No reverse lookup. \r\n")
    
    if args.output != None:
        Path(str(args.output)).touch()
        oFile=open(str(args.output),"w")
        output_Sniff(protocol=tcp,output=oFile)
        oFile.close()
    else:
        print("No output file.\r\n")

else:
    print("Wtf bro ?\r\n")

print("Thanks for using ! Goodbye ! \r\n")

