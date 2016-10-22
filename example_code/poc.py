#! /usr/bin/python2
# coding=utf-8
"""
유전 알고리즘을 이용한 패킷 필터링.
개념 증명 (proof of concept) 코드 입니다.
"""


from pcapy import open_offline

from impacket.ImpactDecoder import EthDecoder

from utility.coverage import counter, timer

AttackPacket = 'test.pcap'
NormalPacket = 'test.pcap'


class Rule:
    """
    Change Python obj to String Rule
    """

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
        def handler(_, __):
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

    all_active_port_rules = list()
    all_inactive_port_rules = list()

    for num in range(1, 65535):
        all_active_port_rules.append(Rule.port(num, True))
        all_inactive_port_rules.append(Rule.port(num, False))

    all_ports = all_active_port_rules + all_inactive_port_rules

    all_src_ips, all_dst_ips = parse_all_ips()

    for src_ip, dst_ip in zip(all_src_ips, all_dst_ips):
        print 1

    all_ip_rules = all_src_ips + all_dst_ips

    return all_ports + all_ip_rules


@timer
def parse_all_ips():
    decoder = EthDecoder()

    all_src_ip = list()
    all_dst_ip = list()

    for pcap in [open_offline(AttackPacket), open_offline(NormalPacket)]:
        while True:
            _, data = pcap.next()
            if _ is None:
                break
            else:
                ip = decoder.decode(data).child()
                try:
                    all_src_ip.append(ip.get_ip_src())
                except AttributeError:
                    print 1
                all_dst_ip.append(ip.get_ip_dst())
    return all_src_ip, all_dst_ip


total_attack = PacketFilter.count_packets(open_offline(AttackPacket)) * 1.0
total_normal = PacketFilter.count_packets(open_offline(NormalPacket)) * 1.0


def main():
    rules = init_rules()

    p = PacketFilter(rules)

    print p
    print p.score


if __name__ == '__main__':
    main()
