# coding=utf-8

from pcapy import open_offline
from random import choice as rand_choice
from random import random, randint

from pcap_manager.get_info import parse_all_ip_port
from utility.coverage import timer, counter


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
MUTATION_PERCENTAGE = 60  # 0 ~ 100


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

    def __to_list(self):
        return [self.src_ip, self.src_ip_active, self.dst_ip, self.dst_ip_active, self.src_port, self.src_port_active,
                self.dst_port, self.dst_port_active]

    @staticmethod
    def no_same_randint(maximum, cnt):
        """
        cnt 만큼 최대 maximum 의 양수를 반환
        :param maximum: 최댓값
        :param cnt: 반환할 데이터의 갯수
        :return: random data by cnt
        """

        data = list()
        maximum -= 1
        for _ in range(cnt):
            while True:
                rand = randint(1, maximum)
                if rand not in data:
                    data.append(rand)
                    break
        return data

    @staticmethod
    def cross2point(list_data1, list_data2):
        length = len(list_data1)

        try:
            assert length == len(list_data2)
        except AssertionError:
            print("Arg list are not same length!!")
            raise
        else:
            arg_data = [list_data1, list_data2]

            # 교차할 포인트 결정
            mix_point = Rule.no_same_randint(length, 2)  # 2 point mix

            source_idx = 0
            source = arg_data[source_idx]

            mix_data = list()

            for idx in range(length):
                if idx in mix_point:
                    try:
                        source = arg_data[source_idx + 1]
                        source_idx += 1
                    except IndexError:
                        source = arg_data[0]
                        source_idx = 0
                mix_data.append(source[idx])

            return mix_data

    def __add__(self, other):
        return Rule(*Rule.cross2point(self.__to_list(), other.__to_list()))

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

    def __add__(self, other):
        new_rule = self.rule + other.rule
        return DNA(new_rule)


class Generation:
    count = 0

    def __init__(self, dna_list):
        Generation.count += 1

        self.level = Generation.count
        self.dna_list = dna_list

        sorted_dna_list = sorted(dna_list, key=lambda x: x.fitness, reverse=True)
        self.__best_dna = sorted_dna_list[0]
        self.__worst_dna = sorted_dna_list[-1]

        # dna_list 가 30개면, 생성할 수 있는 자식 dna 는 (30*29)/2 = 435

    def __repr__(self):
        return "<Generation %d>" % self.level

    def __select_parent(self):
        """
        부모가 될 DNA 를 선출하는 함수.
        선출될 확률은 해당 DNA 의 fitness 값에 비례함.
        :return: DNA object tuple
        """

        parents = list()

        while len(parents) < 2:  # 부모 DNA 가 모두 선출될 때 까지
            for dna in self.dna_list:  # 자신의 dna_list 중에서
                if dna.fitness >= randint(self.worst_dna.fitness, self.best_dna.fitness) \
                        and (len(parents) == 0 or parents[0] != dna):  # 적합도에 비례하게 & 기존에 선출된 DNA 를 제외하고

                    if len(parents) >= 2:
                        break
                    parents.append(dna)  # 선출

            else:
                continue

        return parents[0], parents[1]

    def next(self):
        """
        Goto Next Generation!
        :return: Next level Generation object
        """
        new_generation_dna = list()

        for _ in range(len(self.dna_list)):
            mom, dad = self.__select_parent()
            child = mom + dad
            new_generation_dna.append(child)

        return Generation(new_generation_dna)

    @property
    def best_dna(self):
        return self.__best_dna

    @property
    def worst_dna(self):
        return self.__worst_dna


def main():
    # Init Rule data
    all_src_ip, all_dst_ip, all_src_port, all_dst_port = parse_all_ip_port(['attacks_telnet.pcap'])
    rule_set = [Rule.init_random_rule(all_src_ip, all_dst_ip, all_src_port, all_dst_port) for _ in range(100)]
    first_dna_list = sorted([DNA(rule) for rule in rule_set], key=lambda x: x.fitness, reverse=True)

    g = Generation(first_dna_list)

    for _ in range(500):
        print "Best: %s -> %d\n" % (rand_choice(g.dna_list).rule, g.best_dna.fitness)
        g = g.next()

if __name__ == '__main__':
    main()
