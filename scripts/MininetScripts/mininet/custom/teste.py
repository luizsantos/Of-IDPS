from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController
import datetime

gwLAN='sh ./shHosts/gwLAN.sh'
gwWAN='sh ./shHosts/gwWAN.sh'
router='sh ./shHosts/router.sh'
mirror='sh ./shSwithes/mirror.sh'
qos='sh ./shSwithes/qos.sh'

def ids(host):
  host.sendCmd(ids)
  
def ids(host, apagar):
  host.cmd('killall snort')
  if(apagar=='sim'):
    #host.sendCmd(idsApagaLog)
    date = datetime.datetime.now().strftime("%y%m%d-%H%M%S")
    print 'apagar! um backup ficara em /var/log/bkpSnort/'+date
    host.cmd('mkdir /var/log/bkpSnort/'+date)
    host.cmd('mv /var/log/snort/* /var/log/bkpSnort/'+date)
    host.cmd('rm /var/log/snort/*')
    host.cmd('/usr/sbin/snort -c /etc/snort/snort.conf &')
  else:
    print 'iniciando IDS sem apagar logs'
    host.cmd('/usr/sbin/snort -c /etc/snort/snort.conf &')
    #host.sendCmd(ids)

def desligarIDS(net,h):
    host = net.getNodeByName(h)
    host.cmd('killall snort')
  
def gw(rede, host):
  if rede=='LAN':
    host.cmd(gwLAN)
  else:
    host.cmd(gwWAN) 
    
     
def host1(net):
  host = net.getNodeByName('h1')
  gw('LAN',host)

def host2(net):
  host = net.getNodeByName('h2')
  gw('LAN',host)

def host3(net):
  host = net.getNodeByName('h3')
  gw('LAN',host)
  apagar = raw_input('Deseja zerar arquivos de log do IDS? sim|nao (um backup sera feito)\n')
  ids(host, apagar)
  
def host4(net):
  host = net.getNodeByName('h4')
  host.cmd(router)

def host5(net):
  host = net.getNodeByName('h5')
  gw('WAN',host)

def host6(net):
  host = net.getNodeByName('h6')
  gw('WAN',host)    

def sw1(net):
  sw = net.getNodeByName('s1')
  sw.cmd(qos)
  sw.cmd(mirror)

class MultiSwitch( OVSSwitch ):
    "Custom Switch() subclass that connects to different controllers"
    def start( self, controllers ):
        return OVSSwitch.start( self, [ cmap[ self.name ] ] )  

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
        

	c0 = Controller('c0', ip='192.168.1.113')

        # Add hosts and switches
        lanH1 = self.addHost('h1', ip='10.0.0.1')
        lanH2 = self.addHost('h2', ip='10.0.0.2')
        lanIDS = self.addHost('h3', ip='10.0.0.3')
        lanRouter = self.addHost('h4')
        wanH1 = self.addHost('h5', ip='192.168.0.5')
        wanH2 = self.addHost('h6', ip='192.168.0.6')
        lanSw = self.addSwitch('s1')
        wanSw = self.addSwitch('s2')
  
        # Add links
        self.addLink(lanH1, lanSw)
        self.addLink(lanH2, lanSw)
        self.addLink(lanIDS, lanSw)
        self.addLink(lanRouter, lanSw)
        self.addLink(lanRouter, wanSw)
        self.addLink(wanH1, wanSw)
        self.addLink(wanH2, wanSw)
        #self.addController(c0,wanSw)
        #self.addController(c0,lanSw)
        
		    



  


  
#topos = { 'mytopo': ( lambda: MyTopo() ) }

topologia = MyTopo()
net = Mininet(topo=topologia)
swt1 = net.getNodeByName('s1')
crtl = net.getNodeByName('c0')
net.addController(crtl)
#OVSSwitch.start(crtl,swt1)

net.start()

host1(net)
host2(net)
host3(net)
host4(net)
host5(net)
host6(net)
sw1(net)
CLI( net )
desligarIDS(net,'h3')
net.stop()
exit()