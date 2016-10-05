# -*-coding; utf-8 -*-
from pcapy import open_offline
from impacket.ImpactDecoder import *
from chardet import detect


def handler(_, data):
    eth = EthDecoder().decode(data)
    ip = eth.child()
    proto = ip.child()
    payload = proto.get_data_as_string()

    if payload is not None \
            and payload != '' \
            and detect(payload)['encoding'] == 'ascii':
        pass

    else:
        return None
    source_ip = ip.get_ip_src()
    dest_ip = ip.get_ip_dst()
    # print "Packet detected: %s -> %s" % (source_ip, dest_ip)
    print payload


pcap = open_offline('test.pcap')

pcap.setfilter('tcp ')
pcap.setfilter('ip src not 8.8.8.8')

pcap.loop(0, handler)
