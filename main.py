#! /usr/bin/python2
import time
from pcapy import open_offline

AttackPacket = 'test.pcap'
NormalPacket = 'test.pcap'


def counter(func):
    def wrapper(*args, **kwargs):
        wrapper.called += 1
        return func()

    wrapper.called = 0
    wrapper.__name__ = func.__name__
    return wrapper


def timer(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print "%s : %f" % (func.__name__, (end - start))
        return result

    return wrapper


class Rule:
    def __init__(self):
        pass

    @staticmethod
    def __active_rule(active):
        if active:
            return ""
        else:
            return "not"

    @staticmethod
    def __location_rule(location):
        if location is None:
            return ""
        else:
            return location

    @staticmethod
    def port(port, active, location=None):
        return "%s port %s %d" % (Rule.__location_rule(location), Rule.__active_rule(active), port)

    @staticmethod
    def ip(ip, active, location=None):
        return "ip %s %s %s" % (Rule.__location_rule(location), Rule.__active_rule(active), ip)

    @staticmethod
    def protocol(proto):
        return proto


class PacketFilter:
    def __init__(self, rules):
        self.__rules = rules
        self._attack_pcap = open_offline(AttackPacket)
        self._normal_pcap = open_offline(NormalPacket)
        self.right_detected, self.wrong_detected = self.__check_detected_packet()
        self.__score = self.right_detected - self.wrong_detected

    def __set_rules(self, pcap):
        for rule in self.__rules:
            pcap.setfilter(rule)

    @staticmethod
    def count_packets(pcap):
        @counter
        def handler():
            pass

        pcap.loop(0, handler)

        # return call count
        return handler.called

    def __check_detected_packet(self):
        self.__set_rules(self._attack_pcap)
        right_detected = PacketFilter.count_packets(self._attack_pcap)

        self.__set_rules(self._normal_pcap)
        wrong_detected = PacketFilter.count_packets(self._normal_pcap)

        return right_detected, wrong_detected

    def __repr__(self):
        return "-- <PacketFilter> --" \
               + '\n' + \
               "Detected Attack packet: %f%%" % ((self.right_detected / total_attack) * 100) \
               + '\n' + \
               "Detected Wrong Attack packet %f%%" % ((self.wrong_detected / total_normal) * 100) \
               + '\n--------------------\n'

    @property
    def score(self):
        return self.__score


@timer
def init_rules():
    # all_active_ports = [Rule.port(num, True) for num in range(1, 65536)]
    # all_inactive_ports = [Rule.port(num, False) for num in range(1, 65536)]

    all_active_ports = list()
    all_inactive_ports = list()

    all_src_ips = list()
    all_dst_ips = list()

    for num in range(1, 65535):
        all_active_ports.append(Rule.port(num, True))
        all_inactive_ports.append(Rule.port(num, False))

    all_ports = all_active_ports + all_inactive_ports
    all_ips = all_src_ips + all_dst_ips

    return all_ports + all_ips


total_attack = PacketFilter.count_packets(open_offline(AttackPacket)) * 1.0
total_normal = PacketFilter.count_packets(open_offline(NormalPacket)) * 1.0

if __name__ == '__main__':
    print "Start"
    rules = init_rules()

    p = PacketFilter(rules)
    print p
    print p.score
