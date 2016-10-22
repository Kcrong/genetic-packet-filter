from pcapy import open_offline

from utility.parser import PacketParser


def parse_all_ip_port_mac(packet_filename):
    all_src_ip = set()
    all_dst_ip = set()
    all_src_port = set()
    all_dst_port = set()
    all_src_mac = set()
    all_dst_mac = set()

    pcap_handler = open_offline(packet_filename)

    while True:
        pkt_hdr, pkt_data = pcap_handler.next()

        if pkt_hdr is None:
            break

        p = PacketParser(pkt_data)

        all_src_ip.add(p.src_ip)
        all_dst_ip.add(p.dst_ip)
        all_src_port.add(p.src_port)
        all_dst_port.add(p.dst_port)
        all_src_mac.add(p.src_mac)
        all_dst_mac.add(p.dst_mac)

    return all_src_ip, all_dst_ip, all_src_port, all_dst_port, all_src_mac, all_dst_mac