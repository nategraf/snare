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
    def __init__(self, arpcache, filter=None, iface=None, hwaddr=None, routes=None):
        self.arpcache = arpcache
        self.filter = filter
        self.iface = iface
        self.hwaddr = hwaddr
        self.routes = routes
        self.sniffer = None

    def start(self, sniffer):
        self.sniffer = sniffer

        if self.iface is None:
            self.iface = sniffer.iface
        if self.hwaddr is None:
            self.hwaddr = str(net.ifhwaddr(self.iface))
        if self.routes is None:
            self.routes = net.routes()

    def nexthop(self, ip):
        """Returns the MAC address for the next hop towards the given IP"""
        default = None
        via = None
        for route in self.routes:
            # Save the default route for last
            if route.default():
                default = route
                continue

            if ip in route.dst:
                via = route.via

        if via is None and default is not None:
            via = default.via

        if via is not None:
            return self.arpcache.get(str(via), None)
        return None

    def process(self, pkt):
        if scapy.IP in pkt and scapy.Ether in pkt:
            if pkt[scapy.Ether].dst == self.hwaddr and pkt[scapy.Ether].src != self.hwaddr:
                if pkt[scapy.IP].dst in self.arpcache:
                    hwdst = self.arpcache[pkt[scapy.IP].dst]
                else:
                    hwdst = self.nexthop(pkt[scapy.IP].dst)

                if hwdst is None:
                    logger.debug("Dropping packet %s > %s: next hop unknown", pkt[scapy.IP].src, pkt[scapy.IP].dst)
                    return

                pkt = pkt.copy()
                pkt[scapy.Ether].dst = hwdst

                # After having patched the dst MAC, but before patching the src, apply the filter
                if self.filter is not None:
                    pkt = self.filter(pkt)

                if pkt is None:
                    logger.debug("Filtered packet %s > %s", pkt[scapy.IP].src, pkt[scapy.IP].dst)
                    return

                if pkt is not None:
                    pkt[scapy.Ether].src = self.hwaddr
                    scapy.sendp(pkt, iface=self.iface)
                    logger.debug("Forwarded packet %s > %s to %s", pkt[scapy.IP].src, pkt[scapy.IP].dst, pkt[scapy.Ether].dst)
