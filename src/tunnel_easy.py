"""Easy tunnel program"""
import dpkt
import logging
import socket
import tunnel
import pdb
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr
from scapy.all import send 

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
        #print("Here is the data received..: {}".format(data))
        #TODO: Here is where we would print the contents of the packet using scapy.
        print(IP(data).show())
        send(IP(data))

#        IPPacket = Packet(pkt)a
        #TODO: Here is where we would forward the packet using scapy.

        #TODO: Then, we would take the packet and write it back to the tun..

        leading_bytes = data[:4]
        data = data[4:]  # Strip off the first 4 bytes
        ip_pkt = dpkt.ip.IP(data)
        src = ip_pkt.src
        dst = ip_pkt.dst
        ip_pkt.src = dst
        ip_pkt.dst = src
        data = leading_bytes + ip_pkt.__bytes__()
        t.send(data)
    t.set_rx_handler(echohandler)
    t.monitor()

    try:
        raw_input('Wait indefinitely. Press ctrl-c to quit.')
    except KeyboardInterrupt:
        t.close()


