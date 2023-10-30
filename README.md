# montana_sniffer
 Python homemade sniffer based on Scapy features 


## Install Montana 
To install Montana, you only have to clone the following repository

```bash
git clone https://github.com/kiso6/montana_sniffer.git
cd ./montana_sniffer
sudo ./install.sh
```

## Use Montana 
###  Generic use  
Montana is a commande line based sniffer. You can use as follows:

```bash
usage: montana [-h] [-i INTERFACE] [-t TIMEOUT] [-f FILTER] [-nstat NETSTAT] [-l LIST] [-r REVERSE] [-of OUTPUT]

Montana is a command line sniffer based on Scapy

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Select the interface to sniff on
  -t TIMEOUT, --timeout TIMEOUT
                        Set the length of the sniffing session
  -f FILTER, --filter FILTER
                        Configure the filter applied to the sniffer
  -nstat NETSTAT, --netstat NETSTAT
                        Generates statistics
  -l LIST, --list LIST  Lists the packets captured (highly precise description)
  -r REVERSE, --reverse REVERSE
                        Launch a dig over the source ip addresses
  -of OUTPUT, --output OUTPUT
                        Store the captured packets in output file

example:

# Listen on interface wlan0 during 10min for tcp packets and store everything in logs.txt and reverse IP source of received TCP packets
montana -i wlan0 -t 600 -f tcp -nstat yes -l no -r tcp -of logs

Open Source, made with love by kiso6

```


