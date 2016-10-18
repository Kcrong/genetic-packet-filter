# coding=utf-8
"""
We Need:
    1. Packet Filtering --> Use set_filter() at Pcapy
    2. Filtering Genetic --> Use Random Set. Feature will be IP, Port, Content
    3. Show Graph --> Use pyplot at matplotlib
"""
from pcapy import open_offline

from util import timer, counter


class InvalidRuleException(Exception):
    pass


class SetRule:
    def __init__(self, ip=None, ip_active=None, port=None, port_active=None):
        all_args = locals()

        # Init All local variable
        self.ip = ip
        self.ip_active = ip_active
        self.port = port
        self.port_active = port_active

    def __to_str(self):
        # make ip rule to string
        try:
            assert self.ip_active != self.port_active
        except AssertionError:
            raise InvalidRuleException("Just one rule. one object")

        if self.ip is not None:
            # IP rule
            string = "ip %s" % self.ip
            if self.ip_active is False:
                string = "not " + string
        else:
            # Port Rule
            string = "port %d" % self.port
            if self.port_active is False:
                string = "not " + string

        return string

    def __repr__(self):
        return self.__to_str()

    def __str__(self):
        return self.__to_str()


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


def main():
    rule_set = SetRule(ip='121.142.52.64', ip_active=False)
    print rule_set

if __name__ == '__main__':
    main()
