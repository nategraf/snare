# coding: utf-8
from .sniffer import Module
import scapy.all as scapy
import enum
import threading
import socket
import select
import logging

logger = logging.getLogger(__name__)

class TcpProxyModule(Module):
    """
    TcpProxyModule provides a TCP proxing mechanism using OS sockets, and therefore the kernel's TCP stack.
    The handler provided when constructing this will be called with (client-facing socket, server-facing socket) as args
    """
    def __init__(self, handler, bind, target=None, source=None, backlog=16, timeout=30):
        self.handler = handler
        self.bind = bind
        self.target = target
        self.source = source
        self.backlog = backlog
        self.timeout = timeout

        self._socket = None
        self._thread = None
        self._stopevent = threading.Event()

    def proxy(self, client):
        targetaddr = self.target or client.getsockname()
        sourceaddr = self.source or client.getpeername()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind(sourceaddr)
            server.connect(targetaddr)
            self.handler(client, server)
        except ConnectionError:
            pass
        finally:
            server.close()
            client.close()

    def start(self, sniffer=None):
        self._stopevent.clear()
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self.run, daemon=True)
            self._thread.start()

    def run(self):
        while not self._stopevent.is_set():
            if self._socket is None:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.bind(self.bind)
                self._socket.listen(self.backlog)
                self._socket.settimeout(self.timeout)

            try:
                conn, client = self._socket.accept()
                threading.Thread(target=self.proxy, args=(conn,), daemon=True).start()
            except OSError as e:
                pass

        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def stop(self):
        self._stopevent.set()
        if self._socket is not None:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
            self._socket = None

class TcpFlags(enum.IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

class TcpFlowKey:
    """TcpFlowKey can be used to uniquely identify a TCP flow by source and destination IP address and port"""
    @classmethod
    def frompkt(cls, pkt):
        ip, tcp = pkt[scapy.IP], pkt[scapy.TCP]
        return cls(ip.src, tcp.sport, ip.dst, tcp.dport)

    def __init__(self, src, sport, dst, dport):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport

    def inverse(self):
        return self.__class__(self.dst, self.dport, self.src, self.sport)

    def __hash__(self):
        return hash((self.src, self.sport, self.dst, self.dport))

    def __eq__(self, other):
        return all((
            isinstance(other, self.__class__),
            self.src == other.src,
            self.sport == other.sport,
            self.dst == other.dst,
            self.dport == other.dport
        ))

class TcpFilter:
    """
    TcpFilter wraps a packet filter and adjusts seq and ack numbers to account for altered data lengths
    The wrapped filter should not change the seq or ack number, as they wil be reset
    The wrapped filter may drop a packet by returning None in which case nothing will be forwarded
    """
    def __init__(self, filter=None):
        if filter is not None:
            self.filter = filter

    @property
    def offsets(self):
        # Lazy initialize this field so subclasses don't need to call super().__init__()
        try:
            return self._offsets
        except AttributeError:
            self._offsets = {}
            return self._offsets

    class Offset:
        def __init__(self):
            self.list = []

        def getseq(self, seq):
            offset = 0
            for curr in self.list:
                if curr[0] < seq:
                    offset += curr[1]
                else:
                    break
            return seq + offset

        def getack(self, ack):
            for curr in self.list:
                if curr[0] < ack:
                    ack -= curr[1]
                else:
                    break
            return ack

        def add(self, seq, diff):
            """Add a new entry to the list to account for diff bytes added at seq"""
            # Insert into sorted list using linear search because it will almost always be the front
            new = (seq, diff)
            for i, curr in enumerate(reversed(self.list)):
                if new > curr:
                    self.list.insert(len(self.list) - i, new)
                    break
            else:
                self.list.insert(0, new)

    def filter(self, pkt):
        """filter should be overriden if TcpFilter is subclassed"""
        return pkt

    def __call__(self, pkt):
        if not all(layer in pkt for layer in (scapy.Ether, scapy.IP, scapy.TCP)):
            return pkt

        # Get the TCP seq and ack numbers before the packet is modified.
        seq, ack = pkt[scapy.TCP].seq, pkt[scapy.TCP].ack

        # Retreive any known running offsets for the given flow.
        key = TcpFlowKey.frompkt(pkt)
        if pkt[scapy.TCP].flags & TcpFlags.SYN or key not in self.offsets:
            self.offsets[key] = self.Offset()
        offset = self.offsets[key]

        before = len(pkt[scapy.Raw].load) if scapy.Raw in pkt else 0
        pkt = self.filter(pkt)
        if pkt is None:
            # The packet, and its data, was dropped.
            offset.add(seq, -before)
            return None

        after = len(pkt[scapy.Raw].load) if scapy.Raw in pkt else 0
        diff = after - before
        if diff != 0:
            offset.add(seq, diff)

        pkt[scapy.TCP].seq = offset.getseq(seq)

        # Determine is the ack numbers need to be adjusted by checking the reverse of the stream mapping.
        inverse_key = key.inverse()
        if pkt[scapy.TCP].flags & TcpFlags.ACK and inverse_key in self.offsets:
            pkt[scapy.TCP].ack = self.offsets[inverse_key].getack(ack)

        # Force Scapy to recalculate the checksum.
        pkt[scapy.IP].len += diff
        del pkt[scapy.TCP].chksum
        del pkt[scapy.IP].chksum

        return pkt

def tcpfilter(filter):
    return TcpFilter(filter)
