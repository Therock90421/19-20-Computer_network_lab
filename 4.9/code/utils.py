import os
import sys
import re

from time import sleep, time
from subprocess import Popen, PIPE
from multiprocessing import Process

def config_ip(net):
    h1, h2, r1 = net.get('h1', 'h2', 'r1')
    h1.cmd('ifconfig h1-eth0 10.0.1.11/24')
    h1.cmd('route add default gw 10.0.1.1')

    h2.cmd('ifconfig h2-eth0 10.0.2.22/24')
    h2.cmd('route add default gw 10.0.2.1')

    r1.cmd('ifconfig r1-eth0 10.0.1.1/24')
    r1.cmd('ifconfig r1-eth1 10.0.2.1/24')
    r1.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

    for n in [ h1, h2, r1 ]:
        for intf in n.intfList():
            intf.updateAddr()

def start_tcpprobe(fname):
    print 'Start tcp probe ...'
    os.system('lsmod | grep tcp_probe > /dev/null && rmmod tcp_probe; modprobe tcp_probe port=5001 full=1;')
    Popen('cat /proc/net/tcpprobe > %s' % (fname), shell=True)

def stop_tcpprobe():
    print 'Kill tcp probe ...'
    Popen('killall -9 cat', shell=True).wait()

def monitor_qlen(net, fname):
    r1 = net.get('r1')
    pat = re.compile(r'backlog\s[^\s]+\s([\d]+)p')
    cmd = 'tc -s qdisc show dev r1-eth1'
    with open(fname, 'w') as ofile:
        while 1:
            t = time()
            p = r1.popen(cmd, shell=True, stdout=PIPE)
            output = p.stdout.read()
            matches = pat.findall(output)
            if matches and len(matches) > 1:
                ofile.write('%f, %s\n' % (t, matches[1]))
            sleep(0.01)

def start_qmon(net, fname):
    print 'Start queue monitor ...'
    monitor = Process(target=monitor_qlen, args=(net, fname))
    monitor.start()
    return monitor

def stop_qmon(monitor):
    print 'Stop queue monitor ...'
    monitor.terminate()

def start_iperf(net, duration):
    h1, h2 = net.get('h1', 'h2')
    print 'Start iperf ...'
    server = h2.popen('iperf -s -w 16m')
    client = h1.popen('iperf -c %s -t %d' % (h2.IP(), duration+ 5))

def stop_iperf():
    print 'Kill iperf ...'
    Popen('pgrep -f iperf | xargs kill -9', shell=True).wait()

def start_ping(net, fname):
    print 'Start ping ...'
    h1, h2 = net.get('h1', 'h2')
    ping = h1.popen('ping -i 0.1 %s > %s' % (h2.IP(), fname), shell=True)

def stop_ping():
    print 'Kill ping ...'
    Popen('pgrep -f ping | xargs kill -9', shell=True).wait()

def set_qdisc_algo(net, algo):
    algo_func_dict = {
            'taildrop': [],
            'red': ['tc qdisc add dev r1-eth1 parent 5:1 handle 6: red limit 1000000 avpkt 1000'],
            'codel': ['tc qdisc add dev r1-eth1 parent 5:1 handle 6: codel limit 1000']
            }
    if algo not in algo_func_dict.keys():
        print '%s is not supported.' % (algo)
        sys.exit(1)

    r1 = net.get('r1')
    for func in algo_func_dict[algo]:
        r1.cmd(func)

def dynamic_bw(net, tot_time):
    h2, r1 = net.get('h2', 'r1')

    start_time = time()
    bandwidth = [100,10,1,50,1,100]
    count = 1
    while True:                                              
        sleep(tot_time/6)
        now = time()
        delta = now - start_time
        if delta > tot_time or count >= 6:
            break
        print '%.1fs left...' % (tot_time - delta)
        h2.cmd('tc class change dev h2-eth0 parent 5:0 classid 5:1 htb rate %fMbit burst 15k' % bandwidth[count] )
        r1.cmd('tc class change dev r1-eth1 parent 5:0 classid 5:1 htb rate %fMbit burst 15k' % bandwidth[count] )
        count += 1
    return
