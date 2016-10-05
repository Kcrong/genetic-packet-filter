from txshark import TsharkService
from twisted.python import log

AttackPacket = 'attack.pcap'
NormalPacket = 'normal.pcap'


class PacketFilter(TsharkService):

    def packetReceived(self, packet):
        log.msg("Packet received: {}".format(packet))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
