#!/usr/bin/env python3 

"""
Author: kiso6
License: Open Source
"""

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
parser.add_argument("-v","--verbose",help="Verbose sniffing")


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
protocols=["ssh","ftp","http","https","smtp"]

udp = []
tcp = []
icmp = []
arp = []
dns = []
ssh = []
ftp = []
http = []
https = []
smtp = []


## Flags for tcp traffic
#fin = 0x01;syn=0x02;rst=0x04;psh=0x08;ack=0x10
tcp_flags=[0x00,0x01,0x02,0x04,0x08,0x10,0x11,0x12,0x18]
values=[0,0,0,0,0,0,0,0,0] #fin,syn,rst,psh,ack
def stats_TCP(x):
    for k in range(len(tcp_flags)):
        if x[TCP].flags == tcp_flags[k]:
            values[k]+=1


def print_stats_TCP(stats=values):
    print("**TCP STATS**\r\n")
    print("Nbr of NULL rcvd = "+str(stats[0]))
    print("Nbr of FIN rcvd = "+str(stats[1]))
    print("Nbr of SYN rcvd = "+str(stats[2]))
    print("Nbr of RST rcvd = "+str(stats[3]))
    print("Nbr of PSH rcvd = "+str(stats[4]))
    print("Nbr of ACK rcvd = "+str(stats[5]))
    print("Nbr of FIN-ACK rcvd = "+str(stats[6]))
    print("Nbr of SYN-ACK rcvd = "+str(stats[7]))
    print("Nbr of PSH-ACK rcvd = "+str(stats[8]))
    print("\r\n")

# Op codes for ARP traffic
whohas=0x01;isat=0x02;
arp_rqsts=[0,0]

def stats_ARP(x):
    if x[ARP].op == whohas:
        arp_rqsts[0]+=1
    elif x[ARP].op == isat:
        arp_rqsts[1]+=1
    else:
        print("Unrecognized opcode.")

def print_stats_ARP(tab=arp_rqsts):
    print("**ARP STATS**\r\n")
    print("Nbr of WHO-HAS rqts ="+str(tab[0]))
    print("Nbr of IS-AT rqts ="+str(tab[1]))
    print("\r\n")

# Types for ICMP paquets
icmp_types=np.arange(0,43,1) #from type 0 to 42 refer to https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
icmp_stts=np.zeros(len(icmp_types))
def stats_ICMP(x):
    for k in range(len(icmp_types)):
        if x[ICMP].type == icmp_types[k]:
            icmp_stts[k]+=1
        else:
            print("No Type macthing for this ICMP pckt.")

def print_stats_ICMP(tab=icmp_stts):
    print("**ICMP STATS**\r\n")
    for k in range(len(tab)):
        if tab[k] != 0.0:
            print("Nbr of Type "+str(k)+" rqsts ="+str(tab[k]))
        else:
            print("No rqsts for type"+str(k))
    print("\r\n")

srcIPs=[]

def list_IP(x):
    srcIPs.append(str(x[IP].src))

def shortlistIP(tab):
    return list(set(tab))

def print_IPs(tab):
    print("**List of source IPs**\r\n")
    if len(tab) == 0:
        print("No IP ... Strange behaviour")
    else:
        for k in tab:
            print(k)
    print("\r\n")
        

def reverse_IP(protocol=None):
    for i in range(len(protocol)):
        pqt=protocol[i]
        print("Domain name for pqt n°"+str(i)+":")
        if (pqt.haslayer(IP)):
            os.system("dig -x "+str(pqt[IP].src)+" +short")
        elif (pqt.haslayer(IPv6)):
            os.system("dig -x "+str(pqt[IPv6].src)+" +short")
        else:
            print("No IP layer for pqt n°"+str(i))

# BEGIN OF PRN FUNCTIONS

def store_Packet(x):
    if x.haslayer(IP):
        list_IP(x)
    if x.haslayer(UDP):
        udp.append(x)
    if x.haslayer(TCP):
        tcp.append(x)
        stats_TCP(x)
    if x.haslayer(ICMP):
        icmp.append(x) 
        stats_ICMP(x) 
    if x.haslayer(ARP):
        arp.append(x)
        stats_ARP(x)
    if x.haslayer(DNS):
        dns.append(x)

"""
WORK IN PROGRESS
"""
def check_protocol(x):
    if x.haslayer(TCP):
        match(str(x[TCP].dport)):
            case 22:
                ssh.append(x)
            case 21:
                ftp.append(x)
            case 443:
                http.append(x)
            case 80:
                https.append(x)
            case 587:
                smtp.append(x)
            case others:
                print("No match in port list for current packet.")

def prem_prn(x):
    print(x)#disable for tests
    store_Packet(x)
    #check_protocol(x) WIP

# END OF PRN FUNCTIONS

# STATS FUNCTIONS 

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

# END OF STATS FUNCTIONS

# DISPLAY FUNCTIONS

def display_Net_Stats(udp=None,tcp=None,arp=None,icmp=None,dns=None,http=None,https=None):
    fullScale=total_Packets(udp,tcp,icmp,arp)
    print("Total sniffed packets ="+str(fullScale)+"\r\n")
    print(str(100*compute_Percentage(udp,fullScale))+"% \of UDP \r\n")
    print(str(100*compute_Percentage(tcp,fullScale))+"% \of TCP \r\n")
    print(str(100*compute_Percentage(icmp,fullScale))+"% \of ICMP \r\n")
    print(str(100*compute_Percentage(arp,fullScale))+"% \of ARP \r\n")
    print(str(100*compute_Percentage(dns,fullScale))+"% \of DNS \r\n")
    #print(str(100*compute_Percentage(http,fullScale))+"% \of HTTP \r\n") WIP
    #print(str(100*compute_Percentage(https,fullScale))+"% \of HTTPS \r\n") WIP

def list_Packets(protocol=None):
    if len(protocol) == 0:
        print("Nothing to list \r\n")
        exit(-1)
    for i in range(len(protocol)):
        print("*** PACKET N° " + str(i) + "\r\n" )
        protocol[i].show2()

# END OF DISPLAY FUNCTIONS

# STORAGE FUNCTIONS

def output_Sniff(protocol=None,output=None):
    if len(protocol) == 0:
        print("!!! Nothing to write in log file\r\n")
        exit(-1)
    for i in range(len(protocol)):
        output.write("*** PACKET N° " + str(i) + "\r\n" )
        output.write(str(protocol[i])+"\r\n")

# END OF STORAGE FUNCTIONS


print("*** Welcome to Montana *** \r\n")
selector=input("Do you want to sniff over interface "+args.interface +" during "+args.timeout+" seconds ? [y/N]")


# Only store packets for the moment
if selector=='y' or selector=='Y':
    print("Let's sniff !!!!\r\n")

    sniff(filter=args.filter,count=0,prn=lambda x:prem_prn(x),iface=interface,timeout=tOut)    

    if args.netstat=="yes":
        display_Net_Stats(udp,tcp,arp,icmp,dns,http,https)
        print_stats_TCP(values)
        print_stats_ARP(arp_rqsts)
        print_stats_ICMP(icmp_stts)
        print_IPs(shortlistIP(srcIPs))
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
        case "dns":
            list_Packets(dns)
        case "all":
            list_Packets(udp)
            list_Packets(tcp)
            list_Packets(arp)
            list_Packets(icmp)
            list_Packets(dns)
            #list_Packets(http)
            #list_Packets(https)
        case other:
            print("No list \r\n")
    
    match(args.reverse):
        case "tcp":
            reverse_IP(tcp)
        case "udp":
            reverse_IP(udp) 
        case "icmp":
            reverse_IP(icmp) ## Possibly a non sense
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

