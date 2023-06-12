#coding:utf-8

#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.util import dumpNodeConnections
import time


class CustomTree(Topo):

    "Creating the switches and hosts, then building the tree"

    def build(self):

        #Adding Hosts - Client PC & Client Server
        h1 = self.addHost('h1',ip='10.0.0.1',cls= None,defaultRoute=None,mac="00:00:00:00:00:01")
        h2 = self.addHost('h2',ip='10.0.0.2',cls= None,defaultRoute=None,mac="00:00:00:00:00:02")
        h3 = self.addHost('h3',ip='10.0.0.3',cls= None,defaultRoute=None,mac="00:00:00:00:00:03")
        h4 = self.addHost('h4',ip='10.0.0.4',cls= None,defaultRoute=None,mac="00:00:00:00:00:04")
        h5 = self.addHost('h5',ip='10.0.0.5',cls= None,defaultRoute=None,mac="00:00:00:00:00:05")

        #Adding Switches
        info("Adding Switches\n")
        s1 = self.addSwitch('s1',datapath=None,protocols=None)
        s2 = self.addSwitch('s2',datapath=None,protocols=None)
        s3 = self.addSwitch('s3',datapath=None,protocols=None)
        s4 = self.addSwitch('s4',datapath=None,protocols=None)
        s5 = self.addSwitch('s5',datapath=None,protocols=None)
        s6 = self.addSwitch('s6',datapath=None,protocols=None)
        s7 = self.addSwitch('s7',datapath=None,protocols=None)

        info("Adding Links\n")
        #Adding bandwidth attribute
        self.addLink(s1,s2,cls=TCLink)
        self.addLink(s2,s3,cls=TCLink)
        self.addLink(s3,s4,cls=TCLink)
        self.addLink(s2,s5,cls=TCLink)
        self.addLink(s5,s6,cls=TCLink)
        self.addLink(s6,s7,cls=TCLink)

        #Adding Host Links
        info("Adding Host Links\n")
        self.addLink(s1,h1)
        self.addLink(s4,h2)
        self.addLink(s5,h3)
        self.addLink(s7,h4)
        self.addLink(s7,h5)

def myProgram():

    info("Topology Python Script...\n")
    net = Mininet(topo=CustomTree(), build=False, ipBase='10.0.0.0/8', link=TCLink, autoStaticArp=True, autoSetMacs=True)
    info("Adding the RemoteController\n")
    c0 = net.addController('c0',ip='127.0.0.1', protocol='tcp', controller=RemoteController, port = 6633)
    info("Adding Hosts\n")
    info("Starting network")
    #net.build()
    net.start()
    info( '*** Post configure switches and hosts\n')
    hosts = []
    for item in range(1,5):
        hosts.append(net.get('h{}'.format(item)))
    
    hosts[3].cmd("iperf3 -s &")
    for host in hosts:
        host.cmd("iperf3 -c {0} -b 100k -t 5000 &".format(hosts[3].IP()))

    info('*** Starting switches\n')
    CLI(net)
    net.stop()  


if __name__ == '__main__':
    setLogLevel('info')
    myProgram()