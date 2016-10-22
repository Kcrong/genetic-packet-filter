# -*-coding; utf-8 -*-
from pcapy import open_offline
from impacket.ImpactDecoder import *
from chardet import detect


def handler(_, data):
    eth = EthDecoder().decode(data)
    ip = eth.child()
    proto = ip.child()
    try:
        payload = proto.get_data_as_string()
    except AttributeError:
        return

    if payload is not None \
            and detect(payload)['encoding'] == 'ascii':
        pass

    else:
        return None
    src_ip = ip.get_ip_src()
    dst_ip = ip.get_ip_dst()
    # print "Packet detected: %s -> %s" % (source_ip, dest_ip)
    print payload


pcap = open_offline('../test.pcap')
# https://linux.die.net/man/7/pcap-filter
pcap.setfilter('not arp')

pcap.loop(0, handler)
