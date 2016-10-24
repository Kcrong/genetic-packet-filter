from pcapy import open_offline

from utility.parser import PacketParser
from utility.exception import ignore
from utility.data_manage import return2type, is_iterable


def remove_none(data):
    return [_ for _ in data if _ is not None]


@return2type(list)
@return2type(remove_none)
def parse_all_ip_port(packet_files):
    all_src_ip = set()
    all_dst_ip = set()
    all_src_port = set()
    all_dst_port = set()
    if is_iterable(packet_files) is False:
        packet_files = list(packet_files)

    for packet_file in packet_files:

        pcap_handler = open_offline(packet_file)

        while True:
            pkt_hdr, pkt_data = pcap_handler.next()

            if pkt_hdr is None:
                break

            p = PacketParser(pkt_data)

            # What can i do..?
            with ignore(AttributeError):
                all_src_ip.add(p.src_ip)
            with ignore(AttributeError):
                all_dst_ip.add(p.dst_ip)
            with ignore(AttributeError):
                all_src_port.add(p.src_port)
            with ignore(AttributeError):
                all_dst_port.add(p.dst_port)

    return all_src_ip, all_dst_ip, all_src_port, all_dst_port
