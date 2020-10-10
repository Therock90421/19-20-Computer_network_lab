#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

def clearIP(n):
    for iface in n.intfList():
        n.cmd('ifconfig %s 0.0.0.0' % (iface))

class RingTopo(Topo):
    def build(self):
        b1 = self.addHost('b1')
        b2 = self.addHost('b2')
        b3 = self.addHost('b3')
        b4 = self.addHost('b4')
        b5 = self.addHost('b5')
        b6 = self.addHost('b6')
        b7 = self.addHost('b7')
        b8 = self.addHost('b8')

        self.addLink(b1, b2)
        self.addLink(b1, b3)
        self.addLink(b1, b4)

        self.addLink(b2, b7)
        self.addLink(b3, b6)
        self.addLink(b4, b5)

        self.addLink(b2, b3)
        self.addLink(b3, b4)

        self.addLink(b5, b6)
        self.addLink(b6, b7)

        self.addLink(b8, b7)
        self.addLink(b8, b6)
        self.addLink(b8, b5)

if __name__ == '__main__':
    topo = RingTopo()
    net = Mininet(topo = topo, controller = None) 

    for idx in range(8):
        name = 'b' + str(idx+1)
        node = net.get(name)
        clearIP(node)
        node.cmd('./disable_offloading.sh')
        node.cmd('./disable_ipv6.sh')

        # set mac address for each interface
        for port in range(len(node.intfList())):
            intf = '%s-eth%d' % (name, port)
            mac = '00:00:00:00:0%d:0%d' % (idx+1, port+1)

            node.setMAC(mac, intf = intf)

        node.cmd('./stp > %s-output.txt 2>&1 &' % name)

    net.start()
    CLI(net)
    net.stop()
