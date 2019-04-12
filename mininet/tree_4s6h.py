#!/usr/bin/env python2
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import Intf
from mininet.util import dumpNodeConnections
# from mininet.term import makeTerm

 
REMOTE_CONTROLLER_IP="127.0.0.1"
BW=1000
 
def MininetTopo():
    '''
    Prepare Your Topology
    '''
    net = Mininet (topo=None, link=TCLink, build=False)
 
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           ip=REMOTE_CONTROLLER_IP,
                           port=6633)
 
    info("Create Host node\n")
    h1 = net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
    h3 = net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
    h4 = net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')
    h5 = net.addHost('h5', mac='00:00:00:00:00:05', ip='10.0.0.5')
    h6 = net.addHost('h6', mac='00:00:00:00:00:06', ip='10.0.0.6')
 
    info("Create Switch node\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
 
    BW = 100
    info("Link switch to host\n")
    net.addLink(s1, h1, 4, bw=BW)
    net.addLink(s1, h2, 5, bw=BW)
    net.addLink(s1, h3, 6, bw=BW)
    net.addLink(s3, h4, 4, bw=BW)
    net.addLink(s3, h5, 5, bw=BW)
    net.addLink(s3, h6, 6, bw=BW)
    net.addLink(s1, s2, 1, 1, bw=BW)
    # net.addLink(s2, s3, 2, 1)
    # net.addLink(s3, s4, 2, 2)
    net.addLink(s4, s1, 1, 2, bw=BW)
    net.addLink(s1, s3, 3, 3, bw=BW)
 
 
    '''
    Working your topology
    '''
    info("Start network\n")
    net.build()
    c0.start()
    s1.start( [c0] )
    s2.start( [c0] )
    s3.start( [c0] )
    s4.start( [c0] )

    # info("Start xterm\n")
    # net.terms.append(makeTerm(c0))
     
    info("Dumping host connections\n")
    dumpNodeConnections(net.hosts)
 
    CLI(net)
 
 
    '''
    Clean mininet
    '''
    net.stop()
 
 
if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo()
