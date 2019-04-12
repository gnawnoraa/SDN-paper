from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
import logging
import os

class CustomTopo(Topo):
    "Simple Data Center Topology"

    "linkopts - (1:core, 2:aggregation, 3: edge) parameters"
    "fanout - number of child switch per parent switch"
    def __init__(self,**opts):
        Topo.__init__(self, **opts)
        s=[]
           
        s.append(self.addSwitch('s1', protocols='OpenFlow13'))
        s.append(self.addSwitch('s2', protocols='OpenFlow13'))
        s.append(self.addSwitch('s3', protocols='OpenFlow13'))
        s.append(self.addSwitch('s4', protocols='OpenFlow13')) 
        s.append(self.addSwitch('s5', protocols='OpenFlow13'))
        s.append(self.addSwitch('s6', protocols='OpenFlow13')) 
        s.append(self.addSwitch('s7', protocols='OpenFlow13'))
        s.append(self.addSwitch('s8', protocols='OpenFlow13')) 
        self.addLink(s[0],s[2],bw=100)
        self.addLink(s[0],s[3],bw=100)
        self.addLink(s[1],s[2],bw=100)
        self.addLink(s[1],s[3],bw=100)
        self.addLink(s[2],s[4],bw=100)
        self.addLink(s[2],s[5],bw=100)
        self.addLink(s[3],s[6],bw=100)
        self.addLink(s[3],s[7],bw=100)

        h1=self.addHost('h1',mac='00:00:00:00:00:01')
        h2=self.addHost('h2',mac='00:00:00:00:00:02')
        h3=self.addHost('h3',mac='00:00:00:00:00:03')
        h4=self.addHost('h4',mac='00:00:00:00:00:04')
        h5=self.addHost('h5',mac='00:00:00:00:00:05')
        h6=self.addHost('h6',mac='00:00:00:00:00:06')
        h7=self.addHost('h7',mac='00:00:00:00:00:07')
        h8=self.addHost('h8',mac='00:00:00:00:00:08')
        
        self.addLink(s[4],h1,bw=100)
        self.addLink(s[4],h2,bw=100)
        self.addLink(s[5],h3,bw=100)    
        self.addLink(s[5],h4,bw=100)
        self.addLink(s[6],h5,bw=100)
        self.addLink(s[6],h6,bw=100)
        self.addLink(s[7],h7,bw=100)
        self.addLink(s[7],h8,bw=100)

topos = {'custom': (lambda: CustomTopo())}

def createTopo():
    logging.debug("Create Topo")
    topo = CustomTopo()

    logging.debug("Start Mininet")
    CONTROLLER_IP = "127.0.0.1"
    CONTROLLER_PORT = 6633
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController(
        'controller', controller=RemoteController,
        ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    if os.getuid() != 0:
        logger.debug("You are NOT root")
    elif os.getuid() == 0:
        createTopo()
