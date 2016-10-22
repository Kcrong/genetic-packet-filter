# coding=utf-8

"""
We Need:
    1. Packet Filtering --> Use set_filter() at Pcapy
    2. Filtering Genetic --> Use Random Set. Feature will be IP, Port, Content
    3. Show Graph --> Use pyplot at matplotlib
"""

from pcapy import open_offline
from random import randint

from utility.coverage import timer, counter
from utility.exception import InvalidRuleException
from utility.logging import Logging

from pcap_manager.ip import parse_all_ips, parse_all_ports

logger = Logging()
ATTACKPCAP = 'attacks.pcap'
NORMALPCAP = 'normals.pcap'


class Rule:
    """
    필터링 규칙을 담는 클래스
    """

    def __init__(self, ip=None, ip_active=None, port=None, port_active=None):
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

    @staticmethod
    def random_list(*listset):
        """
        Get Ruleset, Return Random rule
        """
        return listset[randint(0, len(listset))]

    @staticmethod
    def new_rule(*ruleset):
        """
        :param ruleset: 규칙 리스트
        :return: 리스트의 규칙을 조합한 새로운 규칙 (Random Base)
        """
        return Rule(
            ip=Rule.random_list(ruleset).ip,
            ip_active=Rule.random_list(ruleset).ip_active,
            port=Rule.random_list(ruleset).port,
            port_active=Rule.random_list(ruleset).port_active
        )


class Filter:
    def __init__(self, rule):
        self.rules = rule
        self.__score = None

    @timer
    def __run_by_rule(self, pcap):
        # type: (pcap) -> string
        @counter
        def handler(*_):
            # Parsing Packet Data
            pass

        opener = open_offline(pcap)

        for rule in self.rules:
            opener.setfilter(str(rule))
        pcap.loop(0, handler)

        return handler.called

    def _calc_score(self):
        return int(self.__run_by_rule(ATTACKPCAP)) \
               - int(self.__run_by_rule(NORMALPCAP))

    @property
    def score(self):
        if self.__score is None:
            self.__score = self._calc_score()
        else:
            return self.__score


def main():
    rule_set = Rule(ip='121.142.52.64', ip_active=False)
    all_src_ip, all_dst_ip = parse_all_ips('pjhs.pcap')
    all_src_ports, all_dst_ports = parse_all_ports('pjhs.pcap')
    print rule_set


if __name__ == '__main__':
    main()
