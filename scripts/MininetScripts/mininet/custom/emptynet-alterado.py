#!/usr/bin/python

"""
This example shows how to create an empty Mininet object
(without a topology object) and add nodes to it manually.
"""

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# global variables
gwLAN='sh ./shHosts/gwLAN.sh'
gwWAN='sh ./shHosts/gwWAN.sh'
router='sh ./shHosts/router.sh'
mirror='sh ./shSwithes/mirror.sh'
qos='sh ./shSwithes/qos.sh'


# commands for IDS
def ids(host, apagar):
  host.cmd('killall snort')
  if(apagar=='sim'):
    #host.sendCmd(idsApagaLog)
    date = datetime.datetime.now().strftime("%y%m%d-%H%M%S")
    print 'apagar! um backup ficara em /var/log/bkpSnort/'+date+' \n'
    host.cmd('mkdir /var/log/bkpSnort/'+date)
    host.cmd('mv /var/log/snort/* /var/log/bkpSnort/'+date)
    host.cmd('rm /var/log/snort/*')
    host.cmd('/usr/sbin/snort -c /etc/snort/snort.conf &')
  else:
    print 'iniciando IDS sem apagar logs\n'
    host.cmd('/usr/sbin/snort -c /etc/snort/snort.conf &')
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
  gw('LAN',host)

def host2(net):
  info('Configuring host 2\n')
  host = net.getNodeByName('h2')
  gw('LAN',host)

def host3(net):
  info('Configuring host 3\n')
  host = net.getNodeByName('h3')
  gw('LAN',host)
  apagar = raw_input('Deseja zerar arquivos de log do IDS? sim|nao (um backup sera feito)\n')
  ids(host, apagar)
  print '\n'
  
def host4(net):
  info('Configuring host 4\n')
  host = net.getNodeByName('h4')
  host.cmd(router)

def host5(net):
  info('Configuring host 5\n')
  host = net.getNodeByName('h5')
  gw('WAN',host)

def host6(net):
  info('Configuring host 6\n')
  host = net.getNodeByName('h6')
  gw('WAN',host)    

# commands for executing in switches
def sw1(net):
  info('Configuring switch 1\n')
  sw = net.getNodeByName('s1')
  sw.cmd(qos)
  sw.cmd(mirror)
  
def sw2(net):
  info('Configuring switch 2\n')
  sw = net.getNodeByName('s2')

# list of hosts that have commands for executing  
def execCmds(net):
  host1(net)
  host2(net)
  host3(net)
  host4(net)
  host5(net)
  host6(net)
  sw1(net)
  sw2(net)
  print '\n'
  
# Function that contain the network for simulation
def emptyNet():

    "Create an empty network and add nodes to it."

    net = Mininet( controller=Controller )

    info( '*** Adding controller\n' )
    net.addController( 'c0' )

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
    
    info( '*** Executing hosts scripts\n')
    execCmds(net)

    info( '*** Running CLI\n' )
    CLI( net )

    info('*** Stoping IDS process\n')
    desligarIDS(net,'h3')

    info( '*** Stopping network\n' )
    net.stop()
    exit()

# main - start
setLogLevel('info') # enable log in info mode!
emptyNet()
