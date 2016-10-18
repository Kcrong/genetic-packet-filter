# coding=utf-8
"""
We Need:
    1. Packet Filtering --> Use set_filter() at Pcapy
    2. Filtering Genetic --> Use Random Set. Feature will be IP, Port, Content
    3. Show Graph --> Use pyplot at matplotlib
"""
from pcapy import open_offline

from util import timer, counter


class SetRule:
    def __init__(self, ip=None, ip_active=None, port=None, port_active=None):
        all_args = locals()
        for key in all_args:

            # Except self var
            if key == 'self':
                continue

            # Set Attr only not None
            args_data = all_args[key]

            if args_data is not None:
                setattr(self, key, args_data)


class Filter:
    def __init__(self, rule):
        self.rule = rule
        self.__score = 0

    @timer
    def run_by_rule(self, pcap):
        @counter
        def handler(_, __):
            # Parsing Packet Data
            pass

        opener = open_offline(pcap)
        opener.setfilter(self.rule)
        pcap.loop(0, handler)

        return handler.called

    @property
    def score(self):
        return self.__score
