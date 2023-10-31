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
echo "Copy done !"

echo "Installing man page"
manpage=`pwd`$"/montana.1.gz"
mandest="/usr/share/man/man1/"
cp $manpage $mandest
echo "Updating man pages"
mandb
echo "Man page installed"