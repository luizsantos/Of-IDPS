#!/bin/bash
maxBandwidth=100000000
medBandwidth=20000
minBandwidth=10000

switch="$( ovs-vsctl show | grep "Bridge" | sed 's/^[^"]*"\([^"]*\)".*/\1/')"
# TODO make this for all bridges - we need just a for with switch variale! not just s1!
ports="$(ovs-vsctl list-ifaces s1)"
for port in $ports
do
 echo $switch
 echo $port
 ovs-vsctl -- set Port $port qos=@newqos -- \
  --id=@newqos create QoS type=linux-htb other-config:max-rate=$maxBandwidth queues=0=@q0,1=@q1,2=@q2 -- \
  --id=@q0 create Queue other-config:min-rate=$maxBandwidth other-config:max-rate=$maxBandwidth -- \
  --id=@q1 create Queue other-config:min-rate=$medBandwidth other-config:max-rate=$medBandwidth -- \
  --id=@q2 create Queue other-config:min-rate=$minBandwidth other-config:max-rate=$minBandwidth
done



