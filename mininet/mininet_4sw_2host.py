#!/usr/bin/env python2
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import Intf
from mininet.util import dumpNodeConnections

REMOTE_CONTROLLER_IP="192.168.48.134"
def MininetTopo():
    '''
    Prepare Your Topology
    '''
    net = Mininet (topo=None, build=False)
 
    controller = net.addController(name='controller0',
                                    controller=RemoteController,
                                    ip=REMOTE_CONTROLLER_IP,
                                    port=6633)
 
    info("Create Host node\n")
    host1 = net.addHost('host1', ip='10.0.0.1', mac='00:00:00:00:00:01')
    server1 = net.addHost('server1', ip='10.0.0.2', mac='00:00:00:00:00:02')
 
    info("Create Switch node\n")
    switch1 = net.addSwitch('ovs1', protocols='OpenFlow13')
    switch2 = net.addSwitch('ovs2', protocols='OpenFlow13')
    switch3 = net.addSwitch('ovs3', protocols='OpenFlow13')
    switch4 = net.addSwitch('ovs4', protocols='OpenFlow13')
 
    info("Link switch to host\n")
    net.addLink(switch1, switch2, bw=100)
    net.addLink(switch1, switch3)
    net.addLink(switch2, switch4)
    net.addLink(switch3, switch4)
    net.addLink(switch1, host1)
    net.addLink(switch4, server1)
    net.addLink(switch1, switch4)
    net.addLink(switch2, switch3)

 
    '''
    Working your topology
    '''
    info("Start network\n")
    net.start()
 
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