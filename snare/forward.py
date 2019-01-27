# coding: utf-8
from .sniffer import Module
from . import net
import scapy.all as scapy
import enum
import logging

logger = logging.getLogger(__name__)

class ForwarderModule(Module):
    """
    ForwarderModule forwards packets received by the sniffer and in the ARP cache, after applying a filter.
    This serves to forward on packets intercepted, such as by ARP poisoning, onto the intended hosts.
    The filter function should return one packet, a list of packets, or None.
    Returned packets will be sent after having their eithernet addresses set.
    """
    def __init__(self, arpcache, filter=None, iface=None, hwaddr=None):
        self.arpcache = arpcache
        self.filter = filter
        self.iface = iface
        self.hwaddr = hwaddr
        self.sniffer = None

    def start(self, sniffer):
        self.sniffer = sniffer

        if self.iface is None:
            self.iface = sniffer.iface
        if self.hwaddr is None:
            self.hwaddr = str(net.ifhwaddr(self.iface))

    def process(self, pkt):
        if scapy.IP in pkt and scapy.Ether in pkt:
            if pkt[scapy.Ether].dst == self.hwaddr and pkt[scapy.Ether].src != self.hwaddr:
                if pkt[scapy.IP].dst in self.arpcache:
                    pkt = pkt.copy()
                    pkt[scapy.Ether].dst = self.arpcache[pkt[scapy.IP].dst]

                    # After having patched the dst MAC, but before patching the src, apply the filter
                    if self.filter is not None:
                        pkt = self.filter(pkt)

                    if pkt is not None:
                        pkt[scapy.Ether].src = self.hwaddr
                        scapy.sendp(pkt, iface=self.iface)

