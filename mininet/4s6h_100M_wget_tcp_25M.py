#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import Intf
from mininet.util import dumpNodeConnections
from mininet.nodelib import LinuxBridge
from time import sleep
# from mininet.term import makeTerm

 
REMOTE_CONTROLLER_IP="127.0.0.1"
BW=100
 
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
    # s1 = net.addSwitch('s1', cls=LinuxBridge, stp=True, protocols='OpenFlow13')
    # s2 = net.addSwitch('s2', cls=LinuxBridge, stp=True, protocols='OpenFlow13')
    # s3 = net.addSwitch('s3', cls=LinuxBridge, stp=True, protocols='OpenFlow13')
    # s4 = net.addSwitch('s4', cls=LinuxBridge, stp=True, protocols='OpenFlow13')
 
    info("Link switch to host\n")
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
    # net.addLink(s1, h1, 4, bw=BW)
    # net.addLink(s1, h2, 5, bw=BW)
    # net.addLink(s1, h3, 6, bw=BW)
    # net.addLink(s3, h4, 4, bw=BW)
    # net.addLink(s3, h5, 5, bw=BW)
    # net.addLink(s3, h6, 6, bw=BW)    
    net.addLink(s1, h1, 4)
    net.addLink(s1, h2, 5)
    net.addLink(s1, h3, 6)
    net.addLink(s3, h4, 4)
    net.addLink(s3, h5, 5)
    net.addLink(s3, h6, 6)
    net.addLink(s1, s2, 1, 1, bw=BW)
    net.addLink(s2, s3, 2, 1, bw=BW)
    net.addLink(s3, s4, 2, 2, bw=BW)
    net.addLink(s4, s1, 1, 2, bw=BW)
    net.addLink(s1, s3, 3, 3, bw=BW)
    net.addLink(s2, s4, 3, 3, bw=BW)
 
 
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
    # s1.cmd("ovs−vsctl set bridge s1 other_config:stp-priority=0x8000")
    # s2.cmd("ovs−vsctl set bridge s2 other_config:stp-priority=0x9000")
    # s3.cmd("ovs−vsctl set bridge s3 other_config:stp-priority=0xa000")
    # s4.cmd("ovs−vsctl set bridge s4 other_config:stp-priority=0xb000")
    # s1.cmd("ovs-vsctl set bridge s1 stp_enable=true")
    # s2.cmd("ovs-vsctl set bridge s2 stp_enable=true")
    # s3.cmd("ovs-vsctl set bridge s3 stp_enable=true")
    # s4.cmd("ovs-vsctl set bridge s4 stp_enable=true")

    # info("Start xterm\n")
    # net.terms.append(makeTerm(c0))
 
    info("Dumping host connections\n")
    dumpNodeConnections(net.hosts)
    sleep(60)
    print "Testing network connectivity"
    net.pingAll()
    net.pingAll()

    print "Testing wget"
    h1.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h2.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h3.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h4.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h5.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h6.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    sleep(3)
    h1.cmd("python -m SimpleHTTPServer 5001 &")
    h1.cmd("python -m SimpleHTTPServer 5002 &")
    h1.cmd("python -m SimpleHTTPServer 5003 &")
    h1.cmd("python -m SimpleHTTPServer 5004 &")

    h2.cmd("python -m SimpleHTTPServer 5001 &")
    h2.cmd("python -m SimpleHTTPServer 5002 &")
    h2.cmd("python -m SimpleHTTPServer 5003 &")
    h2.cmd("python -m SimpleHTTPServer 5004 &")

    h3.cmd("python -m SimpleHTTPServer 5001 &")
    h3.cmd("python -m SimpleHTTPServer 5002 &")
    h3.cmd("python -m SimpleHTTPServer 5003 &")
    h3.cmd("python -m SimpleHTTPServer 5004 &")
    sleep(1)

    print "wget from h1 to h4 via port 5001"
    h4.cmd("wget --limit-rate=3.125m http://10.0.0.1:5001/625M.log -o h4_tcp_p5001.txt &")
    sleep(10)
    print "wget from h2 to h5 via port 5001"
    h5.cmd("wget --limit-rate=3.125m http://10.0.0.2:5001/625M.log -o h5_tcp_p5001.txt &")
    sleep(10)
    print "wget from h3 to h6 via port 5001"
    h6.cmd("wget --limit-rate=3.125m http://10.0.0.3:5001/625M.log -o h6_tcp_p5001.txt &")
    sleep(10)

    print "wget from h1 to h4 via port 5002"
    h4.cmd("wget --limit-rate=3.125m http://10.0.0.1:5002/625M.log -o h4_tcp_p5002.txt &")
    sleep(10)
    print "wget from h2 to h5 via port 5002"
    h5.cmd("wget --limit-rate=3.125m http://10.0.0.2:5002/625M.log -o h5_tcp_p5002.txt &")
    sleep(10)
    print "wget from h3 to h6 via port 5002"
    h6.cmd("wget --limit-rate=3.125m http://10.0.0.3:5002/625M.log -o h6_tcp_p5002.txt &")
    sleep(10)

    print "wget from h1 to h4 via port 5003"
    h4.cmd("wget --limit-rate=3.125m http://10.0.0.1:5003/625M.log -o h4_tcp_p5003.txt &")
    sleep(10)
    print "wget from h2 to h5 via port 5003"
    h5.cmd("wget --limit-rate=3.125m http://10.0.0.2:5003/625M.log -o h5_tcp_p5003.txt &")
    sleep(10)
    print "wget from h3 to h6 via port 5003"
    h6.cmd("wget --limit-rate=3.125m http://10.0.0.3:5003/625M.log -o h6_tcp_p5003.txt &")
    sleep(10)

    print "wget from h1 to h4 via port 5004"
    h4.cmd("wget --limit-rate=3.125m http://10.0.0.1:5004/625M.log -o h4_tcp_p5004.txt &")
    sleep(10)
    print "wget from h2 to h5 via port 5004"
    h5.cmd("wget --limit-rate=3.125m http://10.0.0.2:5004/625M.log -o h5_tcp_p5004.txt &")
    sleep(10)
    print "wget from h3 to h6 via port 5004"
    h6.cmd("wget --limit-rate=3.125m http://10.0.0.3:5004/625M.log -o h6_tcp_p5004.txt &")

 
    CLI(net)
    '''
    Clean mininet
    '''
    net.stop()
 
 
if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo()
