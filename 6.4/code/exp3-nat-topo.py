#!/usr/bin/python

from mininet.node import OVSBridge
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

class NATTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        n1 = self.addHost('n1')
        n2 = self.addHost('n2')

        self.addLink(h1, n1)
        self.addLink(n2, h2)        
        self.addLink(n1, n2)


if __name__ == '__main__':
    topo = NATTopo()
    net = Mininet(topo = topo, switch = OVSBridge, controller = None) 

    h1, h2, n1, n2 = net.get('h1', 'h2', 'n1', 'n2')

    h1.cmd('ifconfig h1-eth0 10.21.0.1/16')
    h1.cmd('route add default gw 10.21.0.111')

    h2.cmd('ifconfig h2-eth0 10.21.0.1/16')
    h2.cmd('route add default gw 10.21.0.222')

    n1.cmd('ifconfig n1-eth0 10.21.0.111/16')
    n1.cmd('ifconfig n1-eth1 159.226.39.66/24')

    n2.cmd('ifconfig n2-eth0 10.21.0.222/16')
    n2.cmd('ifconfig n2-eth1 159.226.39.233/24')


    for h in (h1, h2):
        h.cmd('./scripts/disable_offloading.sh')
        h.cmd('./scripts/disable_ipv6.sh')

    for n in (n1, n2):
        n.cmd('./scripts/disable_arp.sh')
        n.cmd('./scripts/disable_icmp.sh')
        n.cmd('./scripts/disable_ip_forward.sh')
        n.cmd('./scripts/disable_ipv6.sh')

    #n1.cmd('./nat exp3-n1.conf &')
    #n2.cmd('./nat exp3-n2.conf &')

    #h2.cmd('python2 ./http_server.py &')

    net.start()
    CLI(net)
    net.stop()
