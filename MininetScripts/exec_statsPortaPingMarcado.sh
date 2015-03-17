#!/bin/bash

# comando nomearquivo.pcap portaFiltrada

i=1
mkdir pacotes-$1-Porta$2
for dir in 1403*
do
   tcpstat -r $dir/$1 -f "icmp[icmptype]==8 and ip[1]=1" -o "%R\t%n\n" 1 > pacotes-$1-Porta$2/stat-$dir-Porta$2-$i.txt
   i=$((i+1))
done;

exit 0
