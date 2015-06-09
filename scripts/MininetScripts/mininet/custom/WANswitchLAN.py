"""Custom topology example

Two directly connected switches plus a host for each switch:

   host1 host2 hostIDS(host3)  <--> switchLAN(s1) <--> GW(host4) <--> stichWAN(s2) <--> host5 host6

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Host

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

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

        #h1 = Host('h100')        
        #print h1.cmd('ifconfig')
        #print lanRouter.cmd('sh ./shHosts/router.sh')
        #lanH1.cmd('sh ./shHosts/gwLAN.sh')
        #wanH2.cmd('sh ./shHosts/gwWAN.sh')


topos = { 'mytopo': ( lambda: MyTopo() ) }
