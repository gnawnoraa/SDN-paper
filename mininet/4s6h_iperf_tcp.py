#!/usr/bin/env python2
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import Intf
from mininet.util import dumpNodeConnections
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
    net.addLink(s1, s2, 1, 1)
    net.addLink(s2, s3, 2, 1)
    net.addLink(s3, s4, 2, 2)
    net.addLink(s4, s1, 1, 2)
    net.addLink(s1, s3, 3, 3)
    net.addLink(s2, s4, 3, 3)
 
 
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
    h1.cmd("ping -c 1 10.0.0.6")
    h2.cmd("ping -c 1 10.0.0.4")
    h3.cmd("ping -c 1 10.0.0.5")
    h6.cmd("ping -c 1 10.0.0.1")
    h5.cmd("ping -c 1 10.0.0.3")
    h4.cmd("ping -c 1 10.0.0.2")
    h1.cmd("ping -c 1 10.0.0.6")
    sleep(2)
    print "Testing network connectivity"
    net.pingAll()
    sleep(3)

    print "Testing iperf"
    h1.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h2.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h3.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h4.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h5.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h6.cmd("echo 1 > /proc/sys/net/ipv4/tcp_ecn")
    h4.cmd("iperf -s -p 5001 -i 1 > 'h4_tcp.txt'&")
    h4.cmd("iperf -s -u -p 5001 -i 1 > 'h4_udp.txt' &")
    h5.cmd("iperf -s -p 5001 -i 1 > 'h5_tcp.txt' &")
    h5.cmd("iperf -s -u -p 5001 -i 1 > 'h5_udp.txt' &")
    h6.cmd("iperf -s -p 5001 -i 1 > 'h6_tcp.txt' &")
    h6.cmd("iperf -s -u -p 5001 -i 1 > 'h6_udp.txt' &")
    print "iperf from h1 to h4"
    h1.cmd("iperf -c 10.0.0.4 -t 3600 -i 5 -p 5001 &")
    sleep(10)
    print "iperf from h2 to h5"
    h2.cmd("iperf -c 10.0.0.5 -t 3600 -i 5 -p 5001 &")
    sleep(10)
    print "iperf from h3 to h6"
    h3.cmd("iperf -c 10.0.0.6 -t 3600 -i 5 -p 5001 &")
    
    # sleep(10)
    # print "iperf udp from h1 to h4"
    # h1.cmd("sh udp_to_6.sh &")
    # sleep(10)
    # print "iperf udp from h2 to h5"
    # h2.cmd("sh udp_to_4.sh &")
    # sleep(10)
    # print "iperf udp from h3 to h6"
    # h3.cmd("sh udp_to_5.sh &")
    
    CLI(net)
    '''
    Clean mininet
    '''
    net.stop()
 
 
if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo()
