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

LOGLEVEL = logging.DEBUG
LOGFORMAT = '%(name)s - %(levelname)s - %(message)s'


def dummyhandler(_):
    pass

if __name__ == '__main__':
    logging.basicConfig(format=LOGFORMAT, level=LOGLEVEL)
    t = tunnel.Tunnel(mode='tun')

    def echohandler(data):
        """Echo the received data back to the sender
        but swap source and dest IPs"""
        # Assume it's L3
        leading_bytes = data[:4]
        data = data[4:]  # Strip off the first 4 bytes

        if IP(data).src == "0.0.0.0":
            return #Don't handle broadcasted packets.
        print "Sender: {0}\nReceiver: {1}".format(IP(data).src, IP(data).dst)
        # print "Raw Data as hex: \n"
        # print data.encode('hex')
        # print "\n"
        print IP(data).show()        
        # p = sr(IP(data))

#        IPPacket = Packet(pkt)
        #TODO: Here is where we would forward the packet using scapy.
        #TODO: Then, we would take the packet and write it back to the tun..

        # try:
        #     ip_pkt = dpkt.ip.IP(data)
        # except: 
        #     print("Error: {}".format(sys.exc_info()[0]))
        #     return
        # src = ip_pkt.src
        # dst = ip_pkt.dst
        # ip_pkt.src = dst
        # ip_pkt.dst = src
        # data = leading_bytes + ip_pkt.__bytes__()

        t.send(p)
    t.set_rx_handler(echohandler)
    t.monitor()

    try:
        raw_input('Wait indefinitely. Press ctrl-c to quit.')
    except KeyboardInterrupt:
        t.close()