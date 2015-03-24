#!/bin/bash

switch="$( ovs-vsctl show | grep "Bridge" | cut -c13-14)"

ports="$(ovs-vsctl list-ifaces s1)"
echo $switch
echo $ports


ovs-vsctl -- set Bridge s1 mirrors=@m \
              -- --id=@s1-eth1 get Port s1-eth1 \
              -- --id=@s1-eth2 get Port s1-eth2 \
              -- --id=@s1-eth3 get Port s1-eth3 \
              -- --id=@s1-eth4 get Port s1-eth4 \
              --   --id=@m    create    Mirror    name=mymirror    select-dst-port=@s1-eth1,@s1-eth2,@s1-eth4 select-src-port=@s1-eth1,@s1-eth2,@s1-eth4 output-port=@s1-eth3
