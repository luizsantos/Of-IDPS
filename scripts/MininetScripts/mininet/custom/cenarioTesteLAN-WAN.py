#!/usr/bin/python 
#-*- coding: utf-8 -*-

"""
Simulates a network with a LAN connected to a WAN:

+ The LAN has four hosts, being: 
  - two client/server hosts (h1 and h2); 
  - one IDS host (h3); 
  - and one host to Of-IDPS controller (it's the only host that isn't simulated here).
  
  * The switch from the LAN (s1) is commanded by the OpenFlow controller, that is represented by the Of-IDPS controller. 
    The IP address of the Of-IDPS controller is set by the ipControladorOF variable (if necessary change this value!).
  
+ The WAN has: 
  - two client/server hosts (h5 and h6).
  
  * The switch from the WAN (s2) is commanded by one common local OpenFlow controller (not Of-IDPS).

+ One router (h4) is used to forward packets between LAN and WAN.

h1                                                                            local OpenFlow               h5                                                                  
host1(10.0.0.1)    --------                                                      controller           ----- host5(192.168.0.5)
(00:00:00:00:01:01)        \                                                      127.0.0.1          /     (00:00:00:00:02:05)
                            \                                -Router-                   |           /
h2                           \ s1                             h4                         \     s2  /
host2(10.0.0.2)    -------- switchLAN-------------- (10.0.0.4)host4(192.168.0.4)----------switchWAN
(00:00:00:00:01:02)         /     \        (00:00:00:00:01:04)     (00:00:00:00:02:04              \
                           /       \                                                                \
h3                        /         \                                                                \      h6
host3/IDS(10.0.0.3)-------           remote                                                           ----- host6(192.168.0.6)
(00:00:00:00:01:03)                  Of-IDPS                                                                    (00:00:00:00:02:06)
				    controller


Execute this simulation using the script/command:
 $ ~/executeOfIDPSTests.sh 1 1

"""

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import OVSSwitch, Controller, RemoteController
import datetime
from time import sleep
import threading as t
import os
#sys.path.append('/home/mininet/mininet/custom/testesOF/')

# global variables
gwLAN='sh ./shHosts/gwLAN.sh'
gwWAN='sh ./shHosts/gwWAN.sh'
router='sh ./shHosts/router.sh'
mirror='sh ./shSwithes/mirror.sh'
qos='sh ./shSwithes/qos.sh'
ipControladorOF='192.168.1.157'
#ipControladorOF='10.1.1.157'
date = datetime.datetime.now().strftime("%y%m%d-%H%M%S")


def tcpdump(idhost, net):
    host = net.getNodeByName('h'+idhost)
    host.cmd('tcpdump -i h'+idhost+'-eth0 -s 65535 -w /var/log/tcpdump/'+date+'/host'+idhost+'-eth0.pcap &')
    # For the router get network packets from the two network interfaces.
    if idhost=='4':
      host.cmd('tcpdump -i h'+idhost+'-eth1 -s 65535 -w /var/log/tcpdump/'+date+'/host'+idhost+'-eth1.pcap &')
      
def tcpdumpSwLAN(net):
    host = net.getNodeByName('s1')
    host.cmd('tcpdump -i eth0 -s 65535 -w /var/log/tcpdump/'+date+'/s1-eth0-controller.pcap &')
    host.cmd('tcpdump -i eth1 -s 65535 -w /var/log/tcpdump/'+date+'/s1-eth1-controller.pcap &')
    host.cmd('tcpdump -i s1-eth1 -s 65535 -w /var/log/tcpdump/'+date+'/s1-eth1.pcap &')
    host.cmd('tcpdump -i s1-eth2 -s 65535 -w /var/log/tcpdump/'+date+'/s1-eth2.pcap &')
    host.cmd('tcpdump -i s1-eth3 -s 65535 -w /var/log/tcpdump/'+date+'/s1-eth3.pcap &')
    host.cmd('tcpdump -i s1-eth4 -s 65535 -w /var/log/tcpdump/'+date+'/s1-eth4.pcap &')
    #host.cmd('tcpdump -i s1-eth1 -i s1-eth2 -i s1-eth3 -i s1-eth4 -s 65535 -w /var/log/tcpdump/'+date+'/s1-ethLAN.pcap &')


def tcpdumpAll(net):
    info('*** tcpdump ALL hosts\n')
    tcpdump('1', net)
    tcpdump('2', net)
    #tcpdump('3', net) #Don't capture and log from IDS host.
    tcpdump('4', net)
    tcpdump('5', net)
    tcpdump('6', net)
    tcpdumpSwLAN(net)
  
def tcpdumpKill(net):
    host = net.getNodeByName('h1')
    host.cmd('killall tcpdump')

class thCmd(t.Thread):
  def __init__(self, h, c):
    t.Thread.__init__(self)
    self.host = h
    self.comando = c
  def run(self):
    self.host.cmdPrint(self.comando)
    

# Experiments/tests
def teste1(net):
    textoTeste = """
    test1 - ping (4msgs/each):\nhost1->host6\nhost2->host1\nhost5->host2\nhost6->host5
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    host5 = net.getNodeByName('h5')
    host6 = net.getNodeByName('h6')
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    #Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    
    # Configures the commands that will be simultaneous executed by the threads.
    th1=thCmd(host1,'ping 192.168.0.6 -c 4')
    th2=thCmd(host2,'ping 10.0.0.1 -c 4')
    th5=thCmd(host5,'ping 10.0.0.2 -c 4')
    th6=thCmd(host6,'ping 192.168.0.5 -c 4')
    
    # Execute commands using the threads.
    th1.start()
    th2.start()
    th5.start()
    th6.start()

    # Waiting all commands be executed by the threads.
    th1.join()
    th2.join()
    th5.join()
    th6.join()

    # Finish the network packet capture.
    tcpdumpKill(net)
    return textoTeste

def testePing(net):
    textoTeste = """
    test1 - ping (2msgs):\nhost1->host2
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    
    # Configures the commands that will be simultaneous executed by the threads.
    th1=thCmd(host1,'ping 10.0.0.2 -c 2')
    
    
    # Execute commands using the threads.
    th1.start()
    
    #Espera todos os comandos disparados via thread terminarem!
    th1.join()
    
    sleep(3)
    # Finish the network packet capture.
    tcpdumpKill(net)
    return textoTeste

  
def testeIperfCompararDDoS(net):
    textoTeste = """
    testIperf - iperf:\nhost1->host2(port 80)
    
    Send 10.000 packets from WAN to LAN. This can be used to simulate common packets network (not malicious).
    
    \n\n
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    os.system('mkdir /tmp/alertas/')
    os.system('rm /tmp/alertas/formatted_log.csv')
    
    # Start the server but without threads, otherwise the test won't finish! ;-)
    host2.cmdPrint('iperf -s -p 80 -D')
   
    sleep(5)
   
    # Start the server but without threads, otherwise the test won't finish! ;-)
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+" Start the test : %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('iperf -p 80 -c 10.0.0.2 -t 5')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr

    # Finish the network packet capture.
    sleep(5)
    tcpdumpKill(net)
    return textoTeste  

def testeIperf(net):
    textoTeste = """
    testIperf - iperf:\nhost1->host2(port 80)\nhost3->host2(port 90)
    The 90 network port will pass for three security risk levels: 
      - normal (without security alert), 
      - low, 
      - medium, 
      - and high. 
    This will occur respectively in interval of 30 seconds.
    
    ATTENTION - For now, it doesn't work with the barnyard IDS register log.
    
    \n\n
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    host3 = net.getNodeByName('h3')
    host4 = net.getNodeByName('h4')

    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    os.system('mkdir /tmp/alertas/')
    os.system('rm /tmp/alertas/formatted_log.csv')
    
    # Start the server but without threads, otherwise the test won't finish! ;-)
    host2.cmd('iperf -s -p 90 -D')
    host2.cmd('iperf -s -p 80 -D')
    

    # Configures the commands that will be simultaneous executed by the threads.
    th1=thCmd(host1,'iperf -p 80 -c 10.0.0.2 -t 130')
    th3=thCmd(host3,'iperf -p 90 -c 10.0.0.2 -t 130')
    
        
    # Execute commands using the threads.
    th1.start()
    th3.start()
    
    #
    data1 = datetime.datetime.now()
    #host2.cmdPrint('ping -c 4 -s 92 10.0.0.4')
    textoTeste=textoTeste+"Start test without alerts - normal packets: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    
    tempo = 30
    sleep(tempo)
    
    data2 = datetime.datetime.now()
    host2.cmdPrint('ping -c 4 -s 93 10.0.0.4')
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nLow risk security alert: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    os.system('echo \"11/27-16:56:01.676655,3,[1:1228:7] teste,10.0.0.3,10.0.0.2,TCP,52146,90\" > /tmp/alertas/formatted_log.csv')
    sleep(tempo)
    
    data3 = datetime.datetime.now()
    host2.cmdPrint('ping -c 4 -s 94 10.0.0.4')
    dr=data3-data2
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nMedium risk security alert: %s:%s:%s:%s\n"%(data3.hour,data3.minute,data3.second,data3.microsecond)
    os.system('echo \"11/27-16:56:01.676655,2,[1:1228:7] teste,10.0.0.3,10.0.0.2,TCP,52146,90\" > /tmp/alertas/formatted_log.csv')
    sleep(tempo)
    
    data5 = datetime.datetime.now()
    host2.cmdPrint('ping -c 4 -s 95 10.0.0.4')
    dr=data5-data3
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nHigh risk security alert: %s:%s:%s:%s\n"%(data5.hour,data5.minute,data5.second,data5.microsecond)
    os.system('echo \"11/27-16:56:01.676655,1,[1:1228:7] teste,10.0.0.3,10.0.0.2,TCP,52146,90\" > /tmp/alertas/formatted_log.csv')
    sleep(tempo)
        
    # Waiting all commands be executed by the threads.
    host2.cmdPrint('ping -c 4 -s 95 10.0.0.4')
    os.system('rm /tmp/alertas/formatted_log.csv')
    th1.join()
    th3.join()
    data6 = datetime.datetime.now()
    dr=data6-data5
    textoTeste=textoTeste+"\n Finished! \n\tElapsed time: %s"%dr
    
    # Finish the network packet capture.
    sleep(20)
    tcpdumpKill(net)
    return textoTeste

def teste3(net):
    textoTeste = """
    test3 - idswakeup (know source):\nhost1->host6
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host6 = net.getNodeByName('h6')
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    host1.cmdPrint('idswakeup 10.0.0.1 192.168.0.6 1 70')
    
    # Finish the network packet capture.
    tcpdumpKill(net)
    return textoTeste

def teste4(net):    
    textoTeste = """
    test4 - idswakeup (unknow source):\nhost6->host1
    """
    info(textoTeste)  
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host6 = net.getNodeByName('h6')
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    host6.cmdPrint('idswakeup 0 10.0.0.1 1 70')
    
    # Finish the network packet capture.
    tcpdumpKill(net)
    return textoTeste

def teste5(net):
    textoTeste = """
    test5 -  hyenae -I 1 -a tcp -f s -A 4 -s %-10.0.0.1@\%\%\%\% -d 00:00:00:00:01:02-10.0.0.2@80 -c 100000\n
      host1->host2
    """
    info(textoTeste)
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    #sleep(5)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    #sleep(5)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"First execution: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:01-10.0.0.1@53 -d 00:00:00:00:01:02-10.0.0.2@80 -c 10000 -e 5')
    
    tempo = 10
    #sleep(tempo)
    #host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    #host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:01-10.0.0.1@53 -d 00:00:00:00:01:02-10.0.0.2@80 -c 10000 -e 5')

    #sleep(tempo)
    #host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    
    #host2.cmdPrint('apache2ctl stop')
    # Finish the network packet capture.
    #sleep(10)
    tcpdumpKill(net)
    return textoTeste

def testeDDoSIntInt(net, numberPackets):
    textoTeste = """
    testDDoS LAN->WAN - host1->host2 \n
    """
    
    cmdToExec = "hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:01-10.0.0.1@%%%% -d 00:00:00:00:01:02-10.0.0.2@80 -c %d -e 5 "%numberPackets
    
    textoTeste = textoTeste + cmdToExec
    info(textoTeste)
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
        
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(2)
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 1 10.0.0.2')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
 
    # Start the server but without threads, otherwise the test won't finish! ;-)
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Start at: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint(cmdToExec)
    
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 1 10.0.0.2')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    
    # Finish the network packet capture.
    sleep(10)
    tcpdumpKill(net)
    return textoTeste
  
def testeNewDDoSIntInt(net, numberPackets):
    textoTeste = """
    test DDoS LAN->LAN - host1->host2 \n
    """
    
    #cmdToExec = "hyenae -I 1 -a tcp -f s -s %-%@%%% -d 00:00:00:00:01:02-10.0.0.2@80 -c %d -e 5 "%numberPackets
    cmdToExec = "hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:01-%%@%%%%%% -d 00:00:00:00:01:02-10.0.0.2@80 -c %d -e 10" %numberPackets
    
    
    textoTeste = textoTeste + cmdToExec
    info(textoTeste)
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
        
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(2)
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 1 10.0.0.2')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
 
    # Start the server but without threads, otherwise the test won't finish! ;-)
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Start at: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint(cmdToExec)
    
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 1 10.0.0.2')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    
    # Finish the network packet capture.
    sleep(10)
    tcpdumpKill(net)
    return textoTeste  

def testeDDoSExtInt(net):
    textoTeste = """
    test 5 -  hyenae
      host6->host2
    """
    info(textoTeste)
    # Used hosts.
    host1 = net.getNodeByName('h6')
    host2 = net.getNodeByName('h2')
    
    # Configures the commands that will be simultaneous executed by the threads.
    host2.cmd(host2,'apache2ctl start')
      
    
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(5)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    sleep(5)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Start at: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:02:06-192.168.0.6@%%%% -d 00:00:00:00:02:04-10.0.0.2@80 -c 10000 -e 5 ')
    
    tempo = 10
    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    #textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    #host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:01-10.0.0.1@%%%% -d 00:00:00:00:01:02-10.0.0.2@80 -c 100000 -e 5')

    #sleep(tempo)
    #host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    
    host2.cmdPrint('apache2ctl stop')
    # Finish the network packet capture.
    sleep(30)
    tcpdumpKill(net)
    return textoTeste

def testeDDoSIntExt(net):
    textoTeste = """
    test5 -  hyenae
      host2->host6
    """
    info(textoTeste)
    # Used hosts.
    host1 = net.getNodeByName('h2')
    host2 = net.getNodeByName('h6')
    
    # Configures the commands that will be simultaneous executed by the threads.
    host2.cmd(host2,'apache2ctl start')
    
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(5)
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    sleep(5)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Start at: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:02-10.0.0.2@%%%% -d 00:00:00:00:01:04-192.168.0.6@80 -c 10000 -e 5 ')
    
    tempo = 10
    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    #textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    #host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:01-10.0.0.1@%%%% -d 00:00:00:00:01:02-10.0.0.2@80 -c 100000 -e 5')

    #sleep(tempo)
    #host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    
    host2.cmdPrint('apache2ctl stop')
    # Finish the network packet capture.
    sleep(30)
    tcpdumpKill(net)
    return textoTeste
  
  
def testeDDoSTest1(net):
    textoTeste = """
    testDDoSTest1 hyenae -I 1 -a tcp -f s -A 4 -s %-10.0.0.1@\%\%\%\% -d 00:00:00:00:01:02-10.0.0.2@80 -c 5000\n
      host1->host2
    """
    info(textoTeste)
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(2)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Start at: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:01-10.0.0.1@%%%% -d 00:00:00:00:01:02-10.0.0.2@80 -c 5000 -e 5 ')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    
    # Finish the network packet capture.
    sleep(10)
    tcpdumpKill(net)
    return textoTeste  
  
def testeNMAP(net):
    textoTeste = """
    testNMAP - nmap host1->host2 two times (Interno->Interno)
    \n\n
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')

    tempo = 5
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(tempo)
    
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    host2.cmdPrint('ping -c 4 -s 92 10.0.0.1')
    sleep(tempo)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    host2.cmd('apache2ctl start')
    host2.cmd('iperf -s -p 23 -D')
    host2.cmd('iperf -s -u -p 53 -D')
    

    #
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Start at: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('nmap -A -T4 -O 10.0.0.2 >> /var/log/tcpdump/'+date+'/saidaNmap1.txt')
    

    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    host2.cmdPrint('ping -c 4 -s 92 10.0.0.1')
    
    #data2 = datetime.datetime.now()
    #dr=data2-data1
    #textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    #textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    #host1.cmdPrint('nmap -A -T4 -O 10.0.0.2 >> /var/log/tcpdump/'+date+'/saidaNmap2.txt')
    #sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    host2.cmdPrint('ping -c 4 -s 92 10.0.0.1')
    host2.cmd('apache2ctl stop && killall iperf')
    # Finish the network packet capture.
    sleep(20)
    tcpdumpKill(net)
    return textoTeste


def testeNMAPExternoInterno(net):
    textoTeste = """
    testNMAP - nmap host6->host1 two times
    \n\n
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h6')
    host2 = net.getNodeByName('h1')
    host3 = net.getNodeByName('h2')

    tempo = 5
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(tempo)
    
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host3.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host3.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host3.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')

    
    sleep(tempo)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    host2.cmd('apache2ctl start')
    host2.cmd('iperf -s -p 23 -D')
    host3.cmd('apache2ctl start')
    host3.cmd('iperf -s -p 23 -D')
    

    #
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"First execution: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('nmap -A -T4 -O 10.0.0.1 >> /var/log/tcpdump/'+date+'/saidaNmap1.txt')
    

    sleep(tempo)
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host3.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host3.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host3.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    host1.cmdPrint('nmap -A -T4 -O 10.0.0.2 >> /var/log/tcpdump/'+date+'/saidaNmap2.txt')
    sleep(tempo)
    
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host3.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host3.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host3.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    
    host2.cmd('apache2ctl stop ; killall -s 9 iperf')
    host3.cmd('apache2ctl stop ; killall -s 9 iperf')
    # Finish the network packet capture.
    sleep(20)
    tcpdumpKill(net)
    return textoTeste

def testeNMAPInternoExterno(net):
    textoTeste = """
    testNMAP - nmap host1->host6 two times
    \n\n
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h6')

    tempo = 5
    

            
    # Execute commands using the threads.
    th1.start()
    #
    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(tempo)
    
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    sleep(tempo)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    host2.cmd('apache2ctl start')
    host2.cmd('iperf -s -p 23 -D')
    host2.cmd('iperf -s -u -p 53 -D')
    

    #
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"First execution: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('nmap -A -T4 -O 192.168.0.6 >> /var/log/tcpdump/'+date+'/saidaNmap1.txt')
    

    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    host1.cmdPrint('nmap -A -T4 -O 192.168.0.6 >> /var/log/tcpdump/'+date+'/saidaNmap2.txt')
    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    host2.cmd('apache2ctl stop && killall iperf')
    # Finish the network packet capture.
    sleep(10)
    tcpdumpKill(net)
    return textoTeste  
  
  
  
def testeIDSWakeup(net):
    textoTeste = """
    testIDSWakeup - host1->host2 two times
    \n\n
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    #host2 = net.getNodeByName('h2')

    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(5)
    
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    sleep(1)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    #host2.cmd('apache2ctl start')
    #host2.cmd('iperf -s -p 23 -D')
   

    #
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"First execution: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('idswakeup 10.0.0.1 10.0.0.2 1 70 >> /var/log/tcpdump/'+date+'/saidaIDSWakeup1.txt')
    
    sleep(1)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    host1.cmdPrint('idswakeup 10.0.0.1 10.0.0.2 1 70 >> /var/log/tcpdump/'+date+'/saidaIDSWakeup2.txt')
    #sleep(tempo)
    
    sleep(1)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    #host2.cmd('apache2ctl stop && killall iperf')
    # Finish the network packet capture.
    sleep(20)
    tcpdumpKill(net)
    return textoTeste  
  
def testeIDSWakeupExternoInterno(net):
    textoTeste = """
    testIDSWakeup - host6->host1 two times new (WAN -> LAN)
    \n\n
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h6')
    host2 = net.getNodeByName('h1')

    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(3)
    
    # Because we use ICMP echo packets to better identify the start and stop of tests, but IDSWakeUP use a lot of packets and disturbs this.
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    sleep(5)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    #host2.cmd('apache2ctl start')
    #host2.cmd('iperf -s -p 23 -D')
   

    #
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"First execution: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('idswakeup 192.168.0.6 10.0.0.1 1 70 >> /var/log/tcpdump/'+date+'/saidaIDSWakeup1.txt')
    
    sleep(5)
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    host1.cmdPrint('idswakeup 192.168.0.6 10.0.0.1 1 70 >> /var/log/tcpdump/'+date+'/saidaIDSWakeup2.txt')
    
    sleep(5)
    host1.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -A OUTPUT -p icmp -j TOS --set-tos 1')
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    host1.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    host2.cmd('iptables -t mangle -D OUTPUT -p icmp -j TOS --set-tos 1')
    #host2.cmd('apache2ctl stop && killall iperf')
    # Finish the network packet capture.
    sleep(20)
    tcpdumpKill(net)
    return textoTeste    
  
def testeIDSWakeupInternoExterno(net):
    textoTeste = """
    testIDSWakeup - host1->host6 two times
    \n\n
    """
    info(textoTeste)    
    # Used hosts.
    host1 = net.getNodeByName('h1')
    #host2 = net.getNodeByName('h2')

    
    # Creates a directory to register captured packets.
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    # Get all network packets except from IDS host (h3).
    tcpdumpAll(net)
    sleep(5)
    
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    sleep(5)

    # Start the server but without threads, otherwise the test won't finish! ;-)
    #host2.cmd('apache2ctl start')
    #host2.cmd('iperf -s -p 23 -D')
   

    #
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"First execution: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('idswakeup  10.0.0.1 192.168.0.6 1 70 >> /var/log/tcpdump/'+date+'/saidaIDSWakeup1.txt')
    
    tempo = 10
    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\tElapsed time: %s"%dr
    textoTeste=textoTeste+"\nSecond execution: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    host1.cmdPrint('idswakeup 10.0.0.1 192.168.0.6 1 70 >> /var/log/tcpdump/'+date+'/saidaIDSWakeup2.txt')
    #sleep(tempo)
    
    sleep(5)
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    #host2.cmd('apache2ctl stop && killall iperf')
    # Finish the network packet capture.
    sleep(20)
    tcpdumpKill(net)
    return textoTeste    


  

# IDS commands
def ids(host, apagar):
  #host.cmd('killall snort')
  if(apagar=='yes'):
    #host.sendCmd(idsApagaLog)
    print 'Delete files! A backup will be saved on /var/log/bkpSnort/'+date+' \n'
    host.cmd('mkdir /var/log/bkpSnort/'+date)
    host.cmd('mv /var/log/snort/* /var/log/bkpSnort/'+date)
    host.cmd('rm /var/log/snort/*')
    host.cmd('snort -c /etc/snort/snort.conf -D')
    #sleep(10)
    #host.cmd('barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.log -w /var/log/barnyard2/bylog.waldo -C /etc/snort/classification.config &')
  else:
    print 'Starting IDS without delete log files\n'
    host.cmd('snort -c /etc/snort/snort.conf -D')
    #sleep(5)
    #host.cmd('barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.log -w /var/log/barnyard2/bylog.waldo -C /etc/snort/classification.config &')
  info("""
	 ***********************
	 \n\n IDS Ready!!!!!!!!\n\n
	 ***********************
	 """)
	 
  host.cmd('rm /home/mininet/alertas/formatted_log.csv')
  #sleep(1)
  #host.cmd('python /home/mininet/snort_fast_alert_processor_antigo.py &')
  #host.sendCmd(ids)

def desligarIDS(net,h):
    host = net.getNodeByName(h)
    host.cmd('killall snort')
    #host.cmd('killall python /home/mininet/snort_fast_alert_processor_antigo.py')
    #host.cmd('killall barnyard2')
    sleep(1)
    host.cmd('rm /home/mininet/alertas/formatted_log.csv')

# commands to configure default gateway.
def gw(rede, host):
  if rede=='LAN':
    host.cmd(gwLAN)
  else:
    host.cmd(gwWAN) 

# commands to be executed on the common hosts.
def host1(net):
  info('Configuring host 1\n')
  host = net.getNodeByName('h1')
  host.setMAC('00:00:00:00:01:01')
  gw('LAN',host)

def host2(net):
  info('Configuring host 2\n')
  host = net.getNodeByName('h2')
  host.setMAC('00:00:00:00:01:02')
  gw('LAN',host)

def host3(net):
  info('Configuring host 3\n')
  host = net.getNodeByName('h3')
  host.setMAC('00:00:00:00:01:03')
  gw('LAN',host)
  #apagar = raw_input('Do you want start the simulation with empty IDS files (without old data)? yes/no (a backup of old files will be made)\n')
  ids(host, 'yes')
  
def host4(net):
  info('Configuring host 4\n')
  host = net.getNodeByName('h4')
  host.setMAC('00:00:00:00:01:04', 'h4-eth0')
  host.setMAC('00:00:00:00:02:04', 'h4-eth1')
  host.cmd(router)

def host5(net):
  info('Configuring host 5\n')
  host = net.getNodeByName('h5')
  host.setMAC('00:00:00:00:02:05')
  gw('WAN',host)

def host6(net):
  info('Configuring host 6\n')
  host = net.getNodeByName('h6')
  host.setMAC('00:00:00:00:02:06')
  gw('WAN',host)    

# commands to be executed on the switches.
def sw1(net):
  info('Configuring switch 1\n')
  sw = net.getNodeByName('s1')
  info('=== Installing QoS commands')
  sw.cmdPrint(qos)
  info('=== Mirroring ports to IDS host')
  sw.cmdPrint(mirror)
  
def sw2(net):
  info('Configuring switch 2\n')
  sw = net.getNodeByName('s2')

# list of hosts that have commands for executing  
def execCmds(net):
  host1(net)
  host2(net)
  host3(net) #ids
  host4(net) #router
  host5(net)
  host6(net)
  sw1(net)
  sw2(net)
  print '\n'
  
# Function that contain the network to simulation
def emptyNet():

    "Create an empty network and add nodes to it."

    net = Mininet( controller=Controller)

    info( '*** Adding controller\n' )
    ctrlRemote = RemoteController( 'c0', ip=ipControladorOF )
    net.addController(ctrlRemote)
    info('--> Remote IP controller c0:' + ctrlRemote.IP() +'\n')
    
    #ctrlLocal = RemoteController('c1', port=6633, ip="127.0.0.1")
    ctrlLocal = Controller('c1', port=6634)
    net.addController(ctrlLocal)
    info('--> Local IP controller c1:' + ctrlLocal.IP() +'\n')
    
    
    
    info( '*** Adding hosts\n' )
    lanH1 = net.addHost('h1', ip='10.0.0.1')
    lanH2 = net.addHost('h2', ip='10.0.0.2')
    lanIDS = net.addHost('h3', ip='10.0.0.3')
    lanRouter = net.addHost('h4')
    wanH1 = net.addHost('h5', ip='192.168.0.5')
    wanH2 = net.addHost('h6', ip='192.168.0.6')

    info( '*** Adding switch\n' )
    lanSw = net.addSwitch('s1')
    wanSw = net.addSwitch('s2')

    info( '*** Creating links\n' )
    net.addLink(lanH1, lanSw)
    net.addLink(lanH2, lanSw)
    net.addLink(lanIDS, lanSw)
    net.addLink(lanRouter, lanSw)
    net.addLink(lanRouter, wanSw)
    net.addLink(wanH1, wanSw)
    net.addLink(wanH2, wanSw)
    
    
    

    info( '*** Starting network\n')
    net.start()
    
    info('*** Starting controllers and switches')
    # Configure the LAN switch (s0) to use the remote OpenFlow controller.
    ctrlRemote.start()
    # Use remote OpenFlow controller.
    lanSw.start([ctrlRemote])
    
    # Use local OpenFlow controller
    #info('\n\n\n************ utilizando controlador local para swLAN')
    #lanSw.start([ctrlLocal])
    
    # Configure the WAN switch (s1) to use the local OpenFlow controller.
    ctrlLocal.start()
    wanSw.start([ctrlLocal])
    
    info( '*** Executing hosts scripts\n')
    execCmds(net)
    
    sleep(5) # Wait some seconds to start the IDS.
    
    # Record in a file: the executed test and his start/stop time.
    hst1 = net.getNodeByName('h1')
    hst1.cmdPrint('mkdir /var/log/tcpdump/'+date)
    arquivo = open('/var/log/tcpdump/'+date+'/teste.txt', 'w')
    textoTeste = """
    \n Started at:\n
    """
    data = datetime.datetime.now()
    textoTeste=textoTeste+"%s/%s/%s - %s:%s:%s:%s\n"%(data.year,data.month,data.day,data.hour,data.minute,data.second,data.microsecond)
    arquivo.write(textoTeste)
    
    ### testes a serem executados
		   
    info( '*** Executing Tests\n')
    #textoTeste = textoTeste =teste1(net)
    #textoTeste = testeIperf(net)
    #textoTeste = teste3(net)
    #textoTeste = teste4(net)
    #textoTeste = teste5(net)
    #textoTeste = testeNMAP(net)
    #textoTeste = testeNMAPExternoInterno(net)
    #textoTeste = testeNMAPInternoExterno(net)
    #textoTeste = testeIDSWakeup(net)
    #textoTeste = testeIDSWakeupExternoInterno(net)
    #textoTeste = testeIDSWakeupInternoExterno(net)
    #textoTeste = testeDDoSIntInt(net, 10000)
    textoTeste = testeNewDDoSIntInt(net, 1000)
    #textoTeste = testeDDoSExtInt(net)
    #textoTeste = testeDDoSIntExt(net)
    #testeIperfCompararDDoS(net)
    #testePing(net)
    #testeDDoSTest1(net)
    # Record type of test!
    textoTeste = textoTeste+"""
     
    
    """
    
    arquivo.write(textoTeste)

    ### End of tests!
    
    # Record stop time test.
    data = datetime.datetime.now()
    textoTeste=' \nStopped at:\n '+"%s/%s/%s - %s:%s:%s:%s\n"%(data.year,data.month,data.day,data.hour,data.minute,data.second,data.microsecond)
    arquivo.write(textoTeste)
    arquivo.close()

    info( '*** Running CLI\n' )
    #host1 = net.getNodeByName('h1')
    #host1.cmd("iperf -s -p 80 -D")
    #host1.cmd("iperf -s -p 8080 -D")
    
    # To use the mininet terminal and execute by yourself the commands uncomment the line below:
    #CLI( net )
    sleep(2)
    info('*** Stopping IDS process\n')
    desligarIDS(net,'h3')
    #thIds.join()

    info( '*** Stopping network\n' )
    lanSw.stop()
    ctrlRemote.stop()

    net.stop() 
    exit()

# main - start
setLogLevel('info') # enable log in info mode!
emptyNet()
