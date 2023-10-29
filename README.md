# montana_sniffer
 Python homemade sniffer 


## Install Montana 
To install Montana, you only have to clone the following repository

```bash
git clone https://github.com/kiso6/montana_sniffer.git
```

## Use Montana 
###  Generic use  
Montana is a commande line based sniffer. You can use as follows:

```bash
sudo python3 montana.py argv[1] argv[2] ... argv[5]
```
###  Arguments 

* argv[1] : Logical name of the interface you want to sniff on (wlanX, ethX, ....)  

* argv[2]: Length of the sniffing session in seconds.  

* argv[3]: "-nstat" displays the statistics of the sniffing session  

* argv[4]: "-list" list the content of the captured packets  

* argv[5]: specification of -list option  
        --udp = lists udp packets  
        --tcp = lists tcp packets  
        --arp = lists arp packets  
        --icmp = lists icmp packets  
        --all = lists all the protocols implemented  
        --no = doesn't list any kind of packets  

Example :
```bash
#Listen on wlan0 during 30 seconds, displays the statistical results and list icmp packets captured 

sudo python3 montana.py wlan0 30 -nstat -list --icmp
```


