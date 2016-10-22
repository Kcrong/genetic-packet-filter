import socket
from struct import unpack


class PacketParser:
    def __init__(self, packet):
        # Setting Pre-attr
        # self.parse_ip()
        self.ip_version = None
        self.header_len = None
        self.ttl = None
        self.ip_protocol = None
        self.src_ip = None
        self.dst_ip = None
        self.iph_length = None

        self.packet = packet

        # Parsing Pre-setting
        self.eth_length = 14
        self.icmph_length = 4
        self.udph_length = 8

        eth_protocol, self.src_mac, self.dst_mac = self.parse_ethernet()

        if eth_protocol != 8:
            return

        self.parse_ip()

        self.src_port, self.dst_port, self.data = {
            6: self.parse_tcp,
            17: self.parse_udp
        }[self.ip_protocol]()

    def parse_tcp(self):
        t = self.iph_length + self.eth_length
        tcph = unpack('!HHLLBBHHH', self.packet[t:t + 20])

        src_port = tcph[0]
        dst_port = tcph[1]
        # seq = tcph[2]
        # ack = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4

        h_size = self.eth_length + self.iph_length + tcph_length * 4

        data = self.packet[h_size:]

        return src_port, dst_port, data

    def parse_icmp(self):
        u = self.iph_length + self.eth_length
        icmp_header = self.packet[u:u + 4]

        icmph = unpack('!BBH', icmp_header)

        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]

        h_size = self.eth_length + self.iph_length + self.icmph_length
        data = self.packet[h_size:]

        return icmp_type, code, checksum, data

    def parse_udp(self):
        u = self.iph_length + self.eth_length
        udp_header = self.packet[u:u + 8]
        udph = unpack('!HHHH', udp_header)

        src_port = udph[0]
        dst_port = udph[1]
        # length = udph[2]
        # checksum = udph[3]

        h_size = self.eth_length + self.iph_length + self.udph_length

        data = self.packet[h_size:]

        return src_port, dst_port, data

    def parse_ip(self):
        iph = unpack('!BBHHHBBH4s4s', self.packet[self.eth_length:self.eth_length + 20])
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        return version, ihl, ttl, protocol, s_addr, d_addr, iph_length

    def parse_ethernet(self):
        eth_header = self.packet[:self.eth_length]
        eth = unpack('!6s6sH', eth_header)
        protocol = socket.ntohs(eth[2])
        dst_mac = self.pretty_mac(self.packet[0:6])
        src_mac = self.pretty_mac(self.packet[6:12])
        return protocol, src_mac, dst_mac

    @staticmethod
    def pretty_mac(mac):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            ord(mac[0]), ord(mac[1]), ord(mac[2]), ord(mac[3]), ord(mac[4]), ord(mac[5])
        )
