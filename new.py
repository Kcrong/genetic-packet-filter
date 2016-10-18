# coding=utf-8
"""
We Need:
    1. Packet Filtering --> Use set_filter() at Pcapy
    2. Filtering Genetic --> Use Random Set. Feature will be IP, Port, Content
    3. Show Graph --> Use
"""
from pcapy import open_offline
from util import timer, counter

from impacket.ImpactDecoder import EthDecoder


class Filter:
    def __init__(self, rule):
        self.rule = rule
        self.__score = 0

    @timer
    def run_by_rule(self, pcap):
        @counter
        def handler(_, data):
            # Parsing Packet Data
            pass

        opener = open_offline(pcap)
        opener.setfilter(self.rule)
        pcap.loop(0, handler)

        return handler.called

    @property
    def score(self):
        return self.__score
