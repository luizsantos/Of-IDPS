#!/usr/bin/env python3

"""
Processar um conjunto de arquivos .txt representando estatísticas de rede
agrupadas por segundos (1s) e gera um arquivo .cvs com o dataset com as
seguintes informações:
Time   Stats1  Stats2 ... StatsN
Onde Stats1 ... StatsN são provenientes de cada arquivo .txt

Nota:
 - Os arquivos são gerados pelo comando:
 tcpstat -r data.pcap -f "port 80" -o "%R\t%n\n" 1 > stat1.txt
 - Manter a ordem nos nomes de arquivos

autor: Rodrigo Campiolo
data: 24/03/2014
"""

import os, sys

#se o caminho não for informado por parâmetro, considera o diretório corrente
path = sys.argv[1] if len(sys.argv) > 1 else "."

col_titles = []
dataset = []    # armazena os dados
max_values = 0  # encontra o maior número de linhas

for dir_entry in sorted(os.listdir(path)):
    absolute_path = os.path.join(path, dir_entry)
    if absolute_path.endswith(".txt"):
        col_titles.append(dir_entry)
        print("Processing ...", dir_entry)
        
        with open(absolute_path, 'r') as my_file:
            contents = my_file.readlines()
            packets = []
            for line in contents:
                line = line.rstrip()
                if line != "":
                    fields = line.split("\t")
                    packets.append(int(fields[1])) #adiciona o número de pacotes
            if len(packets) > max_values:
                max_values = len(packets)
            dataset.append(packets)

#cria o arquivo de destino, adiciona o cabeçalho, tempo e dados
merge_stats_file = open(os.path.join(path, "merge_stats.csv"), "w")

header = "Time"
for i in range(0, len(dataset)):
    header += "\t" + col_titles[i]
merge_stats_file.write(header + "\n")
    
for j in range(max_values):
    line = str(j) + "\t"
    for i in range(len(dataset)):
        try:
            value = str(dataset[i][j])
        except:
            value = "-"
        line += value + "\t"
        
    print(line)
    merge_stats_file.write(line + "\n")

merge_stats_file.close()
