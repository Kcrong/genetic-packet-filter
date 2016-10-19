from pcapy import open_offline
from utility.coverage import Counter
from impacket.ImpactDecoder import EthDecoder


def parse_all_ips(packet_filename):
    all_ip = list()

    pcap_handler = open_offline(packet_filename)
    count = Counter()
    while True:
        print count
        _, data = pcap_handler.next()

