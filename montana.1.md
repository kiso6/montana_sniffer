---
title: MONTANA
section: 1
header: User Manual
footer: Montana 1.0.0
date: November 1, 2023
---

# NAME
montana - Montana Sniffer is a command line sniffing tool

# SYNOPSYS
**montana** [*OPTIONS* ]...

# DESCRIPTION
**montana** is a command line sniffer. The main objective of this program is to provide command line interface to practice sniffing and compute statistics on the sniffed network.

# DISCLAIMER 
**montana** should not be used in an illegal way.

# OPTIONS
**-h**
: Display help message

**-i**
: Used to specify the interface you want to sniff on (eth0,wlan0,...)

**-t**
: Specify the length of the sniffing session (in seconds)

**-f**
: Filtering option for Scapy function. Various types of filter are possibles. Please refer to examples or to Scapy documentation.

**-nstat**
: Displays the computed statistics.

**-l**
: Lists the captured packets with highly precise description. Print is based on Scapy show2() function.

**-r**
: Reverse the IP of the DNS requests to find the servers name.

**-of**
: Record the output in a specified file.

**-v**
: Activates the verbose output.

# EXAMPLES

**montana  -i wlan0 -t 15 -f "tcp or udp or arp or icmp" -nstat yes -l no**
: Capture TCP/UDP/ARP/ICMP packets received on interface "wlan0" during 15 seconds and display statistics without listing.  

# AUTHORS
Man page and documentation written by kiso6.  
Scripts developped by kiso6.  

# SEE ALSO
All sources are open and available on *https://github.com/kiso6/montana_sniffer*