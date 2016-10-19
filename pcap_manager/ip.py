from pcapy import open_offline
from utility.coverage import Counter
from impacket.ImpactDecoder import EthDecoder


def parse_all_ips(packet_filename):
    """
    :param packet_filename: pcap filename to parsing
    :return: tuple ([all source ip list], [all destination ip list])
    """
    all_src_ip = list()
    all_dst_ip = list()

    pcap_handler = open_offline(packet_filename)
    decoder = EthDecoder()
    while True:
        _, data = pcap_handler.next()

        if data is None:
            break

        ip = decoder.decode(data).child()  # same as Ethernet.child()

        all_src_ip.append(ip.get_ip_src())
        all_dst_ip.append(ip.get_ip_dst())

    return all_src_ip, all_dst_ip
