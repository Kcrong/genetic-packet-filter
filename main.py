# coding=utf-8
from collections import deque
from pcapy import open_offline, PcapError
from random import choice as rand_choice
from random import randint
from random import random

from matplotlib.animation import FuncAnimation
from matplotlib.pyplot import figure, axes, show, plot
from numpy import mean

from pcap_manager.get_info import parse_all_ip_port
from utility.coverage import timer, counter, Counter
from utility.data_manage import remove_dup_by_key
from utility.exception import CompleteEvolution


def count_pcap_packet(filename):
    pcap = open_offline(filename)

    @counter
    def handler(*_):
        pass

    pcap.loop(0, handler)

    return handler.called

# 진화 세대 수
GENERATION_COUNT = 300

ATTACKPCAP = 'attacks.pcap'
ATTACKPCAP_LEN = count_pcap_packet(ATTACKPCAP)
NORMALPCAP = 'pjhs.pcap'
NORMALPCAP_LEN = count_pcap_packet(NORMALPCAP)
MUTATION_PERCENTAGE = 30  # 0 ~ 100

# Type
SRC = True
DST = False

INIT_PCAP_LIST = [ATTACKPCAP]

ALL_SRC_IP, ALL_DST_IP, ALL_SRC_PORT, ALL_DST_PORT = parse_all_ip_port(INIT_PCAP_LIST)

ALL_IP = ALL_SRC_IP + ALL_DST_IP
ALL_PORT = ALL_SRC_PORT + ALL_DST_PORT

# Visualization
GRAPH_LINE = deque([0], maxlen=GENERATION_COUNT)
GENERATION_LIST = list()
CNT = Counter()


def check_active(active, string):
    if active is False:
        return "not " + string
    else:
        return string


class IP:
    def __init__(self, ip_type, address, active):
        self.type = ip_type
        self.address = address
        self.active = active
        self.__repr_string = self.__make_repr_string()

    def __make_repr_string(self):
        if self.type is SRC:
            string_format = "ip src %s"
        elif self.type is DST:
            string_format = "ip dst %s"
        else:
            raise AssertionError("Invalid ip type Only SRC or DST")

        string = string_format % self.address

        return check_active(self.active, string)

    def __repr__(self):
        return self.__repr_string


class Port:
    def __init__(self, port_type, number, active):
        self.type = port_type
        self.number = number
        self.active = active
        self.__repr_string = self.__make_repr_string()

    def __make_repr_string(self):
        if self.type is SRC:
            string_format = "src port %d"
        elif self.type is DST:
            string_format = "dst port %d"
        else:
            raise AssertionError("Invalid port type Only SRC or DST")

        string = string_format % self.number

        return check_active(self.active, string)

    def __repr__(self):
        return self.__repr_string


# For make Random rule at mutation
MAPDATA = {
    IP: ALL_IP,
    Port: ALL_PORT
}


class Rule:
    """
    필터링 규칙을 담는 클래스
    """
    t_or_f = [True, False]
    filter_attr = [False, True]

    def __init__(self, rule_set):
        self.set_list = list()
        for rule in rule_set:
            if rule not in self.set_list:
                self.set_list.append(rule)

    def __to_str(self):
        return " and ".join([repr(rule) for rule in self.set_list])

    def __repr__(self):
        return self.__to_str()

    def __str__(self):
        return self.__to_str()

    @staticmethod
    def no_same_randint(maximum, cnt):
        """
        cnt 만큼 최대 maximum 의 양수를 반환
        :param maximum: 최댓값
        :param cnt: 반환할 데이터의 갯수
        :return: random data by cnt
        """

        data = list()

        assert maximum > cnt

        for _ in range(cnt):
            while True:
                rand = randint(0, maximum)
                if rand not in data:
                    data.append(rand)
                    break
        return data

    @staticmethod
    def random_ip_or_port():
        rule_type = rand_choice([SRC, DST])
        rule_class = rand_choice([IP, Port])
        active = rand_choice([True, False])

        rule_data = rand_choice(MAPDATA[rule_class])

        return rule_class(rule_type, rule_data, active)

    @staticmethod
    def cross2point(list_data1, list_data2):
        arg_data = [list_data1, list_data2]
        max_length = max([len(list_data1), len(list_data2)])

        # 교차할 포인트 결정
        try:
            mix_point = Rule.no_same_randint(max_length, 2)  # 2 point mix
        except AssertionError:
            return list_data1 + list_data2

        source_idx = 0
        source = arg_data[source_idx]

        mix_data = list()

        for idx in range(max_length):
            if idx in mix_point:
                try:
                    source = arg_data[source_idx + 1]
                    source_idx += 1
                except IndexError:
                    source = arg_data[0]
                    source_idx = 0
            try:
                mix_data.append(source[idx])
            except IndexError:
                pass

        while True:
            # MUTATION!!!
            if MUTATION_PERCENTAGE / 100.0 > random():
                mix_data.append(Rule.random_ip_or_port())
                mix_data.remove(rand_choice(mix_data))
            else:
                break

        return mix_data

    def __add__(self, other):
        return Rule(Rule.cross2point(self.set_list, other.set_list))

    @staticmethod
    def random_t_or_f():
        return rand_choice(Rule.t_or_f)

    @staticmethod
    def init_random_rule(all_src_ip, all_dst_ip, all_src_port, all_dst_port, cnt):
        ip_list = list()
        port_list = list()
        rule_list = list()

        for src_ip, dst_ip in zip(all_src_ip, all_dst_ip):
            ip_list.append(IP(
                rand_choice([SRC, DST]),
                rand_choice([src_ip, dst_ip]),
                Rule.random_t_or_f()))

        for src_port, dst_port in zip(all_src_port, all_dst_port):
            port_list.append(Port(
                rand_choice([SRC, DST]),
                rand_choice([src_port, dst_port]),
                Rule.random_t_or_f()
            ))

        total_list = ip_list + port_list
        total_cnt = len(total_list)

        for i in range(cnt):
            rule_list.append(Rule([rand_choice(total_list) for _ in range(randint(1, total_cnt))]))

        return rule_list


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
        try:
            opener.setfilter(str(self.rule))
        except PcapError as e:
            if e.message == 'expression rejects all packets':
                return 0
            else:
                raise
        opener.loop(0, handler)

        return handler.called

    def _calc_score(self):
        self.detected = int(self.__run_by_rule(ATTACKPCAP))
        self.wrong = int(self.__run_by_rule(NORMALPCAP))

        return (self.detected + (NORMALPCAP_LEN - self.wrong)) - len(self.rule.set_list)

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
        dna_list = remove_dup_by_key(dna_list, lambda x: repr(x.rule))
        Generation.count += 1

        self.level = Generation.count
        self.dna_list = dna_list

        sorted_dna_list = sorted(dna_list, key=lambda x: x.fitness, reverse=True)
        self.__best_dna = sorted_dna_list[0]
        self.__worst_dna = sorted_dna_list[-1]

        self.parent_roulette = self.make_roulette_by_fitness()

        # dna_list 가 30개면, 생성할 수 있는 자식 dna 는 (30*29)/2 = 435

        self.__fitness = self.__calc_generation_fitness()

    def __repr__(self):
        return "<Generation %d>" % self.level

    def __calc_generation_fitness(self):
        return mean([dna.fitness for dna in self.dna_list])

    def make_roulette_by_fitness(self):
        """
        Make list by dna fitness
        :return: list data
        """

        min_fitness = self.worst_dna.fitness - 1
        roulette = list()

        for dna in self.dna_list:
            roulette += [dna for _ in range(dna.fitness - min_fitness)]

        return roulette

    def __select_parent(self):
        """
        부모가 될 DNA 를 선출하는 함수.
        선출될 확률은 해당 DNA 의 fitness 값에 비례함.
        :return: DNA object tuple
        """

        return rand_choice(self.parent_roulette), rand_choice(self.parent_roulette)

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

    @property
    def fitness(self):
        return self.__fitness


# Init Rule data
rule_set = Rule.init_random_rule(ALL_SRC_IP, ALL_DST_IP, ALL_SRC_PORT, ALL_DST_PORT, 100)
first_dna_list = sorted([DNA(rule) for rule in rule_set], key=lambda x: x.fitness, reverse=True)

GENERATION_LIST.append(Generation(first_dna_list))


def visualization(_, l2d):
    generation = GENERATION_LIST[-1]
    print "%s : Best: %s -> %f\n" % (CNT, generation.best_dna.rule, generation.fitness)
    GRAPH_LINE.append(generation.fitness)

    # plot([WE_WANT] * 100, color='red')

    # 다음 세대 적합도 라인 그리기
    l2d.set_data(range(0, len(GRAPH_LINE)), GRAPH_LINE)

    if CNT.count >= GENERATION_COUNT:
        for dna in generation.dna_list:
            print dna.rule
        print "Complete!!"
        print "Best: %s" % generation.best_dna.rule
        raise CompleteEvolution

    GENERATION_LIST.append(generation.next())


def main():
    # Setting Visualization
    fig = figure()

    l1, = axes(xlim=(0, GENERATION_COUNT), ylim=(5000, 13000)).plot([], [])
    ani = FuncAnimation(fig, visualization, fargs=(l1,), interval=50)

    show()


if __name__ == '__main__':
    main()
