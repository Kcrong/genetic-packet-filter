# coding=utf-8

"""
We Need:
    1. Packet Filtering --> Use set_filter() at Pcapy
    2. Filtering Genetic --> Use Random Set. Feature will be IP, Port, Content
    3. Show Graph --> Use pyplot at matplotlib
"""

from pcapy import open_offline
from random import choice as rand_choice

from utility.coverage import timer, counter
from utility.exception import InvalidRuleException
from utility.logging import Logging

from pcap_manager.total import parse_all_ip_port_mac

logger = Logging()
ATTACKPCAP = 'attacks.pcap'
NORMALPCAP = 'normals.pcap'


class Rule:
    """
    필터링 규칙을 담는 클래스
    """

    def __init__(self,
                 src_ip=None,
                 src_ip_active=True,
                 dst_ip=None,
                 dst_ip_active=True,
                 src_port=None,
                 src_port_active=True,
                 dst_port=None,
                 dst_port_active=True
                 ):
        self.src_ip = src_ip
        self.src_ip_active = src_ip_active
        self.dst_ip = dst_ip
        self.dst_ip_active = dst_ip_active
        self.src_port = src_port
        self.src_port_active = src_port_active
        self.dst_port = dst_port
        self.dst_port_active = dst_port_active

    def __to_str(self):
        # make ip rule to string
        string = ""
        if self.src_ip is not None:
            if self.src_ip_active is False:
                string += "not "
            string += "ip src %s " % self.src_ip

        if self.dst_ip is not None:
            if self.dst_ip_active is False:
                string += "not "
            string += "ip dst %s " % self.dst_ip

        if self.src_port is not None:
            if self.src_port_active is False:
                string += "not "
            string += "port src %d " % self.src_port

        if self.dst_port is not None:
            if self.dst_port_active is False:
                string += "not "
            string += "port dst %d " % self.dst_port

        return string

    def __repr__(self):
        return self.__to_str()

    def __str__(self):
        return self.__to_str()

    @staticmethod
    def new_rule(*ruleset):
        """
        :param ruleset: 규칙 리스트
        :return: 리스트의 규칙을 조합한 새로운 규칙 (Random Base)
        """
        return Rule(
            src_ip=rand_choice(ruleset).ip,
            src_ip_active=rand_choice(ruleset).ip_active,
            src_port=rand_choice(ruleset).port,
            src_port_active=rand_choice(ruleset).port_active,
            dst_ip=rand_choice(ruleset).ip,
            dst_ip_active=rand_choice(ruleset).ip_active,
            dst_port=rand_choice(ruleset).port,
            dst_port_active=rand_choice(ruleset).port_active
        )


class Filter:
    def __init__(self, rule):
        if type(rule) != list:
            self.rules = [rule]
        else:
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
    rule_set = Rule(src_ip='121.142.52.64', src_ip_active=False)
    all_src_ip, all_dst_ip, all_src_port, all_dst_port = parse_all_ip_port_mac('pjhs.pcap')
    print rule_set


if __name__ == '__main__':
    main()
