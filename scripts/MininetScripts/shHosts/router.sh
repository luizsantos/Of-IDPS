#!/bin/bash

ifconfig h4-eth0 10.0.0.4
ifconfig h4-eth1 192.168.0.4 
echo 1 > /proc/sys/net/ipv4/ip_forward
