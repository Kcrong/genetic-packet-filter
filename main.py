from pcapy import open_offline

AttackPacket = 'attack.pcap'
NormalPacket = 'Normal.pcap'


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


class PacketFilter:
    def __init__(self, rules):
        self.__rules = rules
        self._attack_pcap = open_offline(AttackPacket)
        self._normal_pcap = open_offline(NormalPacket)
        self.score = self.__calc_score()

    def __set_rules(self, pcap):
        for rule in self.__rules:
            pcap.setfilter(rule)

    @staticmethod
    def counter(func):
        def wrapper(*args, **kwargs):
            wrapper.called += 1
            return func(*args, **kwargs)

        wrapper.called = 0
        wrapper.__name__ = func.__name__
        return wrapper

    @staticmethod
    def __count_packets(pcap):
        @PacketFilter.counter
        def handler(_, data):
            pass

        pcap.loop(0, handler)

        return handler.called

    def __calc_score(self):
        self.__set_rules(self._attack_pcap)
        right_detected = PacketFilter.__count_packets(self._attack_pcap)

        self.__set_rules(self._normal_pcap)
        wrong_detected = PacketFilter.__count_packets(self._normal_pcap)

        return right_detected - wrong_detected
