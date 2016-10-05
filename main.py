from pcapy import open_offline
from impacket.ImpactDecoder import *


def handler(header, data):
    eth = EthDecoder().decode(data)
    ip = eth.child()
    proto = ip.child()
    source_ip = ip.get_ip_src()
    dest_ip = ip.get_ip_dst()
    print "Packet detected: %s -> %s" % (source_ip, dest_ip)


pcap = open_offline('test.pcap')

pcap.setfilter('tcp and port 80')

pcap.loop(0, handler)
