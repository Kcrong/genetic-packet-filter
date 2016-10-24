# coding=utf-8

"""
We Need:
    1. Packet Filtering --> Use set_filter() at Pcapy
    2. Filtering Genetic --> Use Random Set. Feature will be IP, Port, Content
    3. Show Graph --> Use pyplot at matplotlib
"""

from pcapy import open_offline
from random import choice as rand_choice
from random import random

from pcap_manager.total import parse_all_ip_port
from utility.coverage import timer, counter
from utility.logging import Logging

logger = Logging()


def count_pcap_packet(filename):
    pcap = open_offline(filename)

    @counter
    def handler(*_):
        pass

    pcap.loop(0, handler)

    return handler.called


ATTACKPCAP = 'attacks.pcap'
ATTACKPCAP_LEN = count_pcap_packet(ATTACKPCAP)
NORMALPCAP = 'normals.pcap'
NORMALPCAP_LEN = count_pcap_packet(NORMALPCAP)


class Rule:
    """
    필터링 규칙을 담는 클래스
    """
    t_or_f = [True, False]
    filter_attr = [False, True]

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
        rule_data = list()

        if self.src_ip is not None:
            rule = "ip src %s " % self.src_ip

            if self.src_ip_active is False:
                rule = "not " + rule

            rule_data.append(rule)

        if self.dst_ip is not None:
            rule = "ip dst %s" % self.dst_ip

            if self.dst_ip_active is False:
                rule = "not " + rule

            rule_data.append(rule)

        if self.src_port is not None:
            add_format = "src port %d"
            if self.src_port_active is False:
                add_format = "not " + add_format

            rule_data.append(add_format % self.src_port)

        if self.dst_port is not None:
            add_format = "dst port %d"
            if self.dst_port_active is False:
                add_format = "not " + add_format

            rule_data.append(add_format % self.dst_port)

        return " and ".join(rule_data)

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

    @staticmethod
    def init_random_rule(all_src_ip, all_dst_ip, all_src_port, all_dst_port):

        param_data = dict(
            src_ip=None,
            src_port=None,
            dst_ip=None,
            dst_port=None,
            src_ip_active=None,
            src_port_active=None,
            dst_ip_active=None,
            dst_port_active=None
        )
        param_data_keys = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'src_ip_active', 'src_port_active',
                           'dst_ip_active', 'dst_port_active']

        while True:

            for idx, key, data in zip(range(4), param_data_keys, [all_src_ip, all_src_port, all_dst_ip, all_dst_port]):
                if random() > 0.5:
                    param_data[key] = rand_choice(data)
                    param_data[param_data_keys[idx + 4]] = rand_choice(Rule.t_or_f)

            rule = Rule(**param_data)

            if repr(rule) == '':
                continue
            else:
                pass

            for active_key in ['src_ip_active', 'src_port_active', 'dst_ip_active', 'dst_port_active']:
                if param_data[active_key] is True:
                    return rule
            else:
                continue


class Filter:
    def __init__(self, rule):
        self.detected = None  # 탐지한 공격패킷
        self.wrong = None  # 오탐한 일반패킷
        self.rule = rule
        self.__score = self._calc_score()

    @timer
    def __run_by_rule(self, pcap):
        # type: (pcap) -> string
        @counter
        def handler(*_):
            # Parsing Packet Data
            return

        opener = open_offline(pcap)

        opener.setfilter(str(self.rule))
        opener.loop(0, handler)

        return handler.called

    def _calc_score(self):
        score = 0

        self.detected = int(self.__run_by_rule(ATTACKPCAP))
        self.wrong = int(self.__run_by_rule(NORMALPCAP))

        attack_score = ATTACKPCAP_LEN - self.detected
        normal_score = NORMALPCAP_LEN - self.wrong

        score -= attack_score
        score += normal_score

        return score

    @property
    def score(self):
        return self.__score


class DNA:
    def __init__(self, ruleset):
        self.rule = ruleset
        self.filter = Filter(self.rule)

    @property
    def fitness(self):
        return self.filter.score

    def __repr__(self):
        return "<DNA %d fitness>" % self.fitness


class Generation:
    count = 0

    def __init__(self, dna_list):
        Generation.count += 1

        self.level = Generation.count
        self.dna_list = dna_list

    def __repr__(self):
        return "<Generation %d>" % self.level


def main():
    all_src_ip, all_dst_ip, all_src_port, all_dst_port = parse_all_ip_port('output.pcap')

    generation = [Rule.init_random_rule(all_src_ip, all_dst_ip, all_src_port, all_dst_port) for _ in range(100)]
    print generation


if __name__ == '__main__':
    main()
