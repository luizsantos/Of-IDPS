#!/bin/bash

i=1
mkdir pacotes-$1
for dir in 1*
do
   tcpstat -r $dir/$1 -o "%R\t%n\n" 1 > pacotes-$1/stat-$dir-$i.txt
   i=$((i+1))
done;

exit 0
