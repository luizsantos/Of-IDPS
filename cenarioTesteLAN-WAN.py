#!/usr/bin/python

"""
Simulate an internal network and external network. 

The internal network is composed by: host1, host2, host3 that is a IDS, OpenFlow controller Of-IDPS, OpenFlow Switch.

The external network is composed by: host5, host6, Common OpenFlow controller, and OpenFlow Switch. 

Internal and external networks are connected by host4 router.

The OpenFlow switch from external network is comanded by a common OpenFlow controller. 
The OpenFlow switch from internal network can be controlled by a Of-IDPS controller or 
another OpenFlow controller configured by IP configured ipControladorOf variable.

Network topology:

h1                                                                               controlador                h5                                                                  
host1(10.0.0.1)    --------                                                        local              ----- host5(192.168.0.5)
(00:00:00:00:01:01)        \                                                      127.0.0.1          /     (00:00:00:00:02:05)
                            \                                -Roteador-                 |           /
h2                           \ s1                             h4                         \     s2  /
host2(10.0.0.2)    -------- switchLAN-------------- (10.0.0.4)host4(192.168.0.4)----------switchWAN
(00:00:00:00:01:02)         /     \        (00:00:00:00:01:04)     (00:00:00:00:02:04              \
                           /       \                                                                \
h3                        /         \                                                                \      h6
host3/IDS(10.0.0.3)-------           controlador                                                      ----- host6(192.168.0.6)
(00:00:00:00:01:03)                    Remoto                                                                    (00:00:00:00:02:06)
				       Of-IDPS


Run the simulation in the mininet with command:
 sudo mn --custom /home/mininet/mininet/custom/cenarioTesteLAN-WAN.py


Observation 1: after some simulations, the API from mininet some times do not shutdown correctly the OpenFlow controller, 
in this case will appear one message telling that the OpenFlow port is busy, 
to fix this just rerun the command (above) that execute the simulation. 
Or kill then mininet (mn) process in the Linux console.


To execute a test, you need uncomment a test scenario in the end of this script.

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
ipControladorOF='192.168.1.113'
#ipControladorOF='172.16.1.113'
date = datetime.datetime.now().strftime("%y%m%d-%H%M%S")

def tcpdump(idhost, net):
    host = net.getNodeByName('h'+idhost)
    host.cmd('tcpdump -i h'+idhost+'-eth0 -s 65535 -w /var/log/tcpdump/'+date+'/host'+idhost+'-eth0.pcap &')
    #Case route, then capture packets from two interfaces.
    if idhost=='4':
      host.cmd('tcpdump -i h'+idhost+'-eth1 -s 65535 -w /var/log/tcpdump/'+date+'/host'+idhost+'-eth1.pcap &')
      
def tcpdumpSwLAN(net):
    host = net.getNodeByName('s1')
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
    #tcpdump('3', net) #Dont capute/log IDS packets!
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
    

# experimentos/testes
# Ping test.
def teste1(net):
    textoTeste = """
    test 1 - ping (4msgs/for each):\nhost1->host6\nhost2->host1\nhost5->host2\nhost6->host5
    """
    info(textoTeste)    
    #Used hosts
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    host5 = net.getNodeByName('h5')
    host6 = net.getNodeByName('h6')
    
    #Create directory to tcpdump log files (.pcap)
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    #Capture packets from all hosts, except IDS (host3) and switches.
    tcpdumpAll(net)
    
    #Using threads for executing simultaneous commands in hosts
    th1=thCmd(host1,'ping 192.168.0.6 -c 4')
    th2=thCmd(host2,'ping 10.0.0.1 -c 4')
    th5=thCmd(host5,'ping 10.0.0.2 -c 4')
    th6=thCmd(host6,'ping 192.168.0.5 -c 4')
    
    #Start commands by threads
    th1.start()
    th2.start()
    th5.start()
    th6.start()

    #Wait threads finish
    th1.join()
    th2.join()
    th5.join()
    th6.join()

    #Finish tcpdump command (logs)
    tcpdumpKill(net)
    return textoTeste

#experiment 1
def testeIperf(net):
    textoTeste = """
    testeIperf - iperf:\nhost1->host2(porta 80)\nhost3->host2(porta 90)
    Port 90 will be considered normal in the first 30 seconds, 
    data rate flow will be softly restricted in 60 seconds, 
    data rate will be severely (hard) restricted in 90 seconds and blocked in 120 seconds.
    
    \n\n
    """
    info(textoTeste)    
    #Used hosts
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    host3 = net.getNodeByName('h3')
    host4 = net.getNodeByName('h4')

    
    #Create directory to tcpdump log files (.pcap)
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    #Capture packets from all hosts, except IDS (host3) and switches.
    tcpdumpAll(net)
    
    os.system('rm /tmp/alertas/formatted_log.csv')
    
    #Start servers without use threads
    host2.cmd('iperf -s -p 90 -D')
    host2.cmd('iperf -s -p 80 -D')
    

    #Using threads for executing simultaneous commands in hosts
    th1=thCmd(host1,'iperf -p 80 -c 10.0.0.2 -t 130')
    th3=thCmd(host3,'iperf -p 90 -c 10.0.0.2 -t 130')
    
        
    #Start commands by threads
    th1.start()
    th3.start()
    
    #
    data1 = datetime.datetime.now()
    #host2.cmdPrint('ping -c 4 -s 92 10.0.0.4')
    textoTeste=textoTeste+"Inicio de teste sem alertas: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    
    tempo = 30
    sleep(tempo)
    
    data2 = datetime.datetime.now()
    host2.cmdPrint('ping -c 4 -s 93 10.0.0.4')
    dr=data2-data1
    textoTeste=textoTeste+"\n\ttempo decorrido: %s"%dr
    textoTeste=textoTeste+"\nInicio de teste sem alertas: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    os.system('echo \"11/27-16:56:01.676655,3,[1:1228:7] teste,10.0.0.3,10.0.0.2,TCP,52146,90\" > /tmp/alertas/formatted_log.csv')
    sleep(tempo)
    
    data3 = datetime.datetime.now()
    host2.cmdPrint('ping -c 4 -s 94 10.0.0.4')
    dr=data3-data2
    textoTeste=textoTeste+"\n\ttempo decorrido: %s"%dr
    textoTeste=textoTeste+"\nAtiva alerta prioridade 3 em: %s:%s:%s:%s\n"%(data3.hour,data3.minute,data3.second,data3.microsecond)
    os.system('echo \"11/27-16:56:01.676655,2,[1:1228:7] teste,10.0.0.3,10.0.0.2,TCP,52146,90\" > /tmp/alertas/formatted_log.csv')
    sleep(tempo)
    
    data5 = datetime.datetime.now()
    host2.cmdPrint('ping -c 4 -s 95 10.0.0.4')
    dr=data5-data3
    textoTeste=textoTeste+"\n\ttempo decorrido: %s"%dr
    textoTeste=textoTeste+"\nAtiva alerta prioridade 2 em: %s:%s:%s:%s\n"%(data5.hour,data5.minute,data5.second,data5.microsecond)
    os.system('echo \"11/27-16:56:01.676655,1,[1:1228:7] teste,10.0.0.3,10.0.0.2,TCP,52146,90\" > /tmp/alertas/formatted_log.csv')
    sleep(tempo)
        
    #Wait finish threads commands
    host2.cmdPrint('ping -c 4 -s 95 10.0.0.4')
    os.system('rm /tmp/alertas/formatted_log.csv')
    th1.join()
    th3.join()
    data6 = datetime.datetime.now()
    dr=data6-data5
    textoTeste=textoTeste+"\n terminou! \n\ttempo decorrido: %s"%dr
    
    #Finish tcpdump command (logs)
    sleep(20)
    tcpdumpKill(net)
    return textoTeste


#experiment 2
def testeDDoSExtInt(net):
    textoTeste = """
    test  -  hyenae
      host6->host2
    """
    info(textoTeste)
    #Used hosts
    host1 = net.getNodeByName('h6')
    host2 = net.getNodeByName('h2')
    
    #Start servers without use threads (or its commands do not stop)
    host2.cmd(host2,'apache2ctl start')
    
    
    #Create directory to tcpdump log files (.pcap)
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    #Capture packets from all hosts, except IDS (host3) and switches.
    tcpdumpAll(net)
    sleep(5)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    sleep(5)

    # run a command
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Inicio de teste alertas em tempo de execucao: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:02:06-192.168.0.6@%%%% -d 00:00:00:00:02:04-10.0.0.2@80 -c 10000 -e 5 ')
    
    tempo = 10
    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 10.0.0.2')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\ttempo decorrido: %s"%dr
    
    host2.cmdPrint('apache2ctl stop')
    #Finish tcpdump command (logs)
    sleep(30)
    tcpdumpKill(net)
    return textoTeste

def testeDDoSIntExt(net):
    textoTeste = """
    test -  hyenae
      host2->host6
    """
    info(textoTeste)
    #Used hosts
    host1 = net.getNodeByName('h2')
    host2 = net.getNodeByName('h6')
    
    #Start servers without use threads (or its commands do not stop)
    host2.cmd(host2,'apache2ctl start')
    
    
    #Create directory to tcpdump log files (.pcap)
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    #Capture packets from all hosts, except IDS (host3) and switches.
    tcpdumpAll(net)
    sleep(5)
    
    #Run commands
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    sleep(5)

    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Inicio de teste alertas em tempo de execucao: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:02-10.0.0.2@%%%% -d 00:00:00:00:01:04-192.168.0.6@80 -c 10000 -e 5 ')
    
    tempo = 10
    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\ttempo decorrido: %s"%dr
    
    host2.cmdPrint('apache2ctl stop')
    #Finish tcpdumps
    sleep(30)
    tcpdumpKill(net)
    return textoTeste

def testeDDoSIntInt(net):
    textoTeste = """
    test -  hyenae
      host1->host2
    """
    info(textoTeste)
    #Used hosts
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    
    #Start servers without use threads (or its commands do not stop)
    host2.cmd(host2,'apache2ctl start')
    
    
    #Create directory to tcpdump log files (.pcap)
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    #Capture packets from all hosts, except IDS (host3) and switches.
    tcpdumpAll(net)
    sleep(5)
    
    #Run commands
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    sleep(5)

    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Inicio de teste alertas em tempo de execucao: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('hyenae -I 1 -a tcp -f s -A 4 -s 00:00:00:00:01:01-10.0.0.1@%%%% -d 00:00:00:00:01:02-10.0.0.2@80 -c 10000 -e 5 ')
    
    tempo = 10
    sleep(tempo)
    host1.cmdPrint('ping -c 4 -s 92 192.168.0.6')
    
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\ttempo decorrido: %s"%dr
    
    host2.cmdPrint('apache2ctl stop')
    #Finish tcpdumps
    sleep(30)
    tcpdumpKill(net)
    return textoTeste
  
#experiment 3  
def testeIDSWakeupExternoInterno(net):
    textoTeste = """
    test IDSWakeup - host6->host1 twice times
    \n\n
    """
    info(textoTeste)    
    #Used hosts
    host1 = net.getNodeByName('h6')
    host2 = net.getNodeByName('h1')

    
    #Create directory to tcpdump log files (.pcap)
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    #Capture packets from all hosts, except IDS (host3) and switches.
    tcpdumpAll(net)
    sleep(5)
    
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    sleep(5)
    #First execution
    data1 = datetime.datetime.now()
    textoTeste=textoTeste+"Inicio de teste alertas em tempo de execucao: %s:%s:%s:%s\n"%(data1.hour,data1.minute,data1.second,data1.microsecond)
    host1.cmdPrint('idswakeup 192.168.0.6 10.0.0.1 1 70 >> /var/log/tcpdump/'+date+'/saidaIDSWakeup1.txt')
    
    sleep(5)
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    #Second execution
    data2 = datetime.datetime.now()
    dr=data2-data1
    textoTeste=textoTeste+"\n\ttempo decorrido: %s"%dr
    textoTeste=textoTeste+"\nInicio de teste com alertas instalados: %s:%s:%s:%s\n"%(data2.hour,data2.minute,data2.second,data2.microsecond)
    host1.cmdPrint('idswakeup 192.168.0.6 10.0.0.1 1 70 >> /var/log/tcpdump/'+date+'/saidaIDSWakeup2.txt')
    
    sleep(10)
    host1.cmdPrint('ping -c 3 -s 92 10.0.0.1')
    host2.cmdPrint('ping -c 3 -s 92 192.168.0.6')
    #Finish tcpdump command (logs)
    sleep(20)
    tcpdumpKill(net)
    return textoTeste    
  

# commands for IDS
def ids(host, apagar):
  #host.cmd('killall snort')
  if(apagar=='sim'):
    #host.sendCmd(idsApagaLog)
    print 'Delete! a backup will be in /var/log/bkpSnort/'+date+' \n'
    host.cmd('mkdir /var/log/bkpSnort/'+date)
    host.cmd('mv /var/log/snort/* /var/log/bkpSnort/'+date)
    host.cmd('rm /var/log/snort/*')
    host.cmd('snort -c /etc/snort/snort.conf -D')
  else:
    print 'starting IDS without delete logs\n'
    host.cmd('snort -c /etc/snort/snort.conf -D')
  info("""
	 ***********************
	 \n\n IDS READY!!!!!!!!\n\n
	 ***********************
	 """)
    #host.sendCmd(ids)

def desligarIDS(net,h):
    host = net.getNodeByName(h)
    host.cmd('killall snort')

# command for configuring default gateway
def gw(rede, host):
  if rede=='LAN':
    host.cmd(gwLAN)
  else:
    host.cmd(gwWAN) 

# Commands for executing in hosts
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
  #apagar = raw_input('Deseja zerar arquivos de log do IDS? sim|nao (um backup sera feito)\n')
  ids(host, 'sim')
  
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

# commands for executing in switches
def sw1(net):
  info('Configuring switch 1\n')
  sw = net.getNodeByName('s1')
  info('=== Aplicando QoS')
  sw.cmdPrint(qos)
  info('=== Espelhando Portas')
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
  
# Function that contain the network for simulation
def emptyNet():

    "Create an empty network and add nodes to it."

    net = Mininet( controller=Controller)

    info( '*** Adding controller\n' )
    ctrlRemote = RemoteController( 'c0', ip=ipControladorOF )
    net.addController(ctrlRemote)
    info('--> remote IP controller - c0:' + ctrlRemote.IP() +'\n')
    
    #ctrlLocal = RemoteController('c1', port=6633, ip="127.0.0.1")
    ctrlLocal = Controller('c1', port=6634)
    net.addController(ctrlLocal)
    info('--> local IP controller - c1:' + ctrlLocal.IP() +'\n')
    
    
    
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
    #link remote controller to s0 internal network swith
    ctrlRemote.start()
    #use remote controller
    lanSw.start([ctrlRemote])
    
    #use local controller
    #info('\n\n\n************ using local controller for swLAN')
    #lanSw.start([ctrlLocal])
    
    #start local controller to switch from s1 external network
    ctrlLocal.start()
    wanSw.start([ctrlLocal])
    
    info( '*** Executing hosts scripts\n')
    execCmds(net)
    
    sleep(5) # wai 5 seconds to start IDS!
    
    #log tests in files, the name of file and directory will be composed by date/time of start execution of test
    hst1 = net.getNodeByName('h1')
    hst1.cmdPrint('mkdir /var/log/tcpdump/'+date)
    arquivo = open('/var/log/tcpdump/'+date+'/teste.txt', 'w')
    textoTeste = """
    Test -
    \n Begin at:\n
    """
    data = datetime.datetime.now()
    textoTeste=textoTeste+"%s/%s/%s as %s:%s:%s:%s\n"%(data.year,data.month,data.day,data.hour,data.minute,data.second,data.microsecond)
    arquivo.write(textoTeste)
    
    ### Tests
    
    #
    # Start the testes here!
    #
    # Select the test to run. For that uncomment the line of the desired test.
	   
    info( '*** Executing Tests\n')
    textoTeste = textoTeste =teste1(net)
    #textoTeste = testeIperf(net)
    #textoTeste = testeIDSWakeupExternoInterno(net)
    #textoTeste = testeDDoSExtInt(net)
    #textoTeste = testeDDoSIntExt(net)
    #textoTeste = testeDDoSIntInt(net)
    
    # record attack test!
    textoTeste = textoTeste+"""
     
    put comment of test here
    
    """
    
    arquivo.write(textoTeste)

    ### end of test!
    
    # register the time that test was finished
    data = datetime.datetime.now()
    textoTeste=' \nFinished at:\n '+"%s/%s/%s as %s:%s:%s:%s\n"%(data.year,data.month,data.day,data.hour,data.minute,data.second,data.microsecond)
    arquivo.write(textoTeste)
    arquivo.close()

    info( '*** Running CLI\n' )
    #Uncomment below line for execute the test with CLI console
    #CLI( net )
    sleep(5)
    info('*** Stoping IDS process\n')
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
