from pcapy import open_offline
from utility.exception import ignore
from impacket.ImpactDecoder import EthDecoder


def parse_all_ips(packet_filename):
    """
    :param packet_filename: pcap filename to parsing
    :return: tuple ([all source ip list], [all destination ip list])
    """
    all_src_ip = set()
    all_dst_ip = set()

    pcap_handler = open_offline(packet_filename)
    decoder = EthDecoder()
    while True:
        _, data = pcap_handler.next()

        if _ is None:
            break

        ip = decoder.decode(data).child()  # same as Ethernet.child()
        with ignore(AttributeError):
            all_src_ip.add(ip.get_ip_src())
            all_dst_ip.add(ip.get_ip_dst())

    return list(all_src_ip), list(all_dst_ip)


def parse_all_ports(packet_filename):
    """
    :param packet_filename:
    :return:
    """

    all_src_ports = set()
    all_dst_ports = set()

    pcap_handler = open_offline(packet_filename)
    decoder = EthDecoder()
    while True:
        _, data = pcap_handler.next()

        if _ is None:
            break

        tcp = decoder.decode(data).child().child()
        with ignore(AttributeError):
            all_src_ports.add(tcp.get_th_sport())
            all_dst_ports.add(tcp.get_th_dport())

    return list(all_src_ports), list(all_dst_ports)
