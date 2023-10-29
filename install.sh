#!/bin/bash

pip install scapy
pip install numpy
pip install matplotlib

sniffer=`pwd`$"/montana.py"
dest="/usr/local/bin"
rnm="montana"

echo "Copying "$sniffer" in "$dest
cp $sniffer $dest
mv $dest$"/montana.py" $dest$"/montana"
chmod u+x $dest$"/montana"
echo "Install done !"