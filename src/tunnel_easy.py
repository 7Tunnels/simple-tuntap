"""Easy tunnel program"""
import dpkt
import logging
import socket
import tunnel
import pdb
import binascii
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr
from scapy.all import send 
import sys
import os

LOGLEVEL = logging.DEBUG
LOGFORMAT = '%(name)s - %(levelname)s - %(message)s'


def dummyhandler(_):
    pass

if __name__ == '__main__':
    logging.basicConfig(format=LOGFORMAT, level=LOGLEVEL)
    t = tunnel.Tunnel(mode='tun')
    # t1 = tunnel.Tunnel(mode='tun')
    def echohandler(data):
        """Echo the received data back to the sender
        but swap source and dest IPs"""
        # Assume it's L3
        leading_bytes = data[:4]
        data = data[4:]  # Strip off the first 4 bytes that aren't IP layer bytes.
        
        if IP(data).src == "0.0.0.0" or IP(data).dst == "0.0.0.0":
            return #Don't handle broadcasted packets.
        print "Packet on tun0"
        print "Sender: {0}\nReceiver: {1}".format(IP(data).src, IP(data).dst)
        pkt = IP(data)
        if pkt.src == '192.168.40.1':
            pkt.src = '192.168.1.106'
            del pkt.chksum #deleting this and calling show2 recalculates the chksum.
            
        print IP(pkt).show2()
        send(IP(pkt), iface="tun0")
        # send(IP(pkt), iface="tun1")
        
        # t.send(p)
    def echohandler1(data):
        leading_bytes = data[:4]
        data = data[4:]  # Strip off the first 4 bytes that aren't IP layer bytes.

        if IP(data).src == "0.0.0.0" or IP(data).dst == "0.0.0.0":
            return #Don't handle broadcasted packets.
        print "Packet on tun1"
        print "Sender: {0}\nReceiver: {1}".format(IP(data).src, IP(data).dst)
        pkt = IP(data)
        return

    os.system('ip address add 192.168.40.1/32 dev tun0') #Sets tun0's IP address as 192.168.40.1
    os.system('ip route add 192.168.40.2/32 dev tun0') #Says any traffic to 192.168.40.2, forward to tun0.
    os.system('ip route add default 192.168.40.0/24 via 192.168.1.106') #Set the default route for 192.168.40.0/24 to go through this machine's ip address

    # os.system('ip address add 192.168.40.3/32 dev tun1')
    # os.system('ip route add 192.168.40.4/32 dev tun1')

    os.system('sudo ip route add 18.223.239.214 dev tun0')
    os.system('sudo iptables -A FORWARD -i wlp1s0 -o tun0 -j ACCEPT')
    # os.system('sudo iptables -A FORWARD -i tun1 -o wlp1s0 -m state --state ESTABLISHED,RELATED -j ACCEPT')
    # os.system('sudo iptables -t nat -A POSTROUTING -o tun1 -j MASQUERADE')
   
    t.set_rx_handler(echohandler)
    t.monitor()

    # t1.set_rx_handler(echohandler1)
    # t1.monitor()

    try:
        raw_input('Wait indefinitely. Press ctrl-c to quit.')
    except KeyboardInterrupt:
        t.close()