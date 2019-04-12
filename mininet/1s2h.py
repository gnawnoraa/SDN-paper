#!/usr/bin/env python2
import re
import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info, error
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import Intf
from mininet.util import dumpNodeConnections, quietRun
# from mininet.term import makeTerm

 
REMOTE_CONTROLLER_IP="127.0.0.1"
BW=100
def checkIntf(intf):
    #make sure intface exists and is not configured.
    if(' %s:'% intf) not in quietRun('ip link show'):
        error('Error:', intf, 'does not exist!\n' )
        exit(1)
    ips = re.findall( r'\d+\.\d+\.\d+\.\d+', quietRun   ( 'ifconfig ' + intf ) )
    if ips:
        error("Error:", intf, 'has an IP address,'
            'and is probably in use!\n')
        exit(1)

def MininetTopo():
    '''
    Prepare Your Topology
    '''
    # intfName = "eth1"
    # checkIntf(intfName)

    net = Mininet(topo=None, link=TCLink, build=False)
 
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           ip=REMOTE_CONTROLLER_IP,
                           port=6633)
 
    info("Create Host node\n")
    h1 = net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
 
    info("Create Switch node\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # _intf = Intf(intfName, node=s1)
 
    info("Link switch to host\n")
    # net.addLink(s1, h1, 1, bw=BW)
    # net.addLink(s2, h2, 1, bw=BW)
    # net.addLink(s3, h3, 1, bw=BW)
    # net.addLink(s4, h4, 1, bw=BW)
    # net.addLink(s1, s2, 2, 2)
    # net.addLink(s2, s3, 3, 3)
    # net.addLink(s3, s4, 4, 4)
    # net.addLink(s4, s1, 2, 3)
    # net.addLink(s1, s3, 4, 2)
    # net.addLink(s2, s4, 4, 3)
    
    # net.addLink(s1, h1, 4, bw=BW)
    # net.addLink(s1, h2, 5, bw=BW)
    # net.addLink(s1, h3, 6, bw=BW)
    # net.addLink(s3, h4, 4, bw=BW)
    # net.addLink(s3, h5, 5, bw=BW)
    # net.addLink(s3, h6, 6, bw=BW)
    # net.addLink(s1, s2, 1, 1, bw=BW)
    # net.addLink(s2, s3, 2, 1, bw=BW)
    # net.addLink(s3, s4, 2, 2, bw=BW)
    # net.addLink(s4, s1, 1, 2, bw=BW)
    # net.addLink(s1, s3, 3, 3, bw=BW)
    # net.addLink(s2, s4, 3, 3, bw=BW)
    net.addLink(s1, h1, bw=BW)
    net.addLink(s1, h2, bw=BW)
 
 
    '''
    Working your topology
    '''
    info("Start network\n")
    net.build()
    c0.start()
    s1.start( [c0] )

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
