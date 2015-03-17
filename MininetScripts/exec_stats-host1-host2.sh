#!/bin/bash
echo "hos1 -> host2"
~/exec_stats.sh host1-eth0.pcap
~/exec_stats.sh host2-eth0.pcap

echo "join host1"
cd pacotes-host1-eth0.pcap/
~/junta_arquivos_colunas.py

echo "join host2"
cd ../pacotes-host2-eth0.pcap/
~/junta_arquivos_colunas.py