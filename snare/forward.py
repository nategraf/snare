# coding: utf-8
from .sniffer import Module
from . import net
import scapy.all as scapy
import enum
import logging
import base64

logger = logging.getLogger(__name__)

class ForwarderModule(Module):
    """
    ForwarderModule forwards packets received by the sniffer and in the ARP cache, after applying a filter.
    This serves to forward on packets intercepted, such as by ARP poisoning, onto the intended hosts.
    The filter function should return one packet, a list of packets, or None.
    Returned packets will be sent after having their eithernet addresses set.
    """
    def __init__(self, arpcache, filter=None, iface=None, hwaddr=None, ipaddr=None, routes=None):
        self.arpcache = arpcache
        self.filter = filter
        self.iface = iface
        self.hwaddr = hwaddr
        self.ipaddr = ipaddr
        self.routes = routes
        self.sniffer = None

    def start(self, sniffer):
        self.sniffer = sniffer

        if self.iface is None:
            self.iface = sniffer.iface
        if self.hwaddr is None:
            self.hwaddr = str(net.ifhwaddr(self.iface))
        if self.ipaddr is None:
            self.ipaddr = str(net.ifaddr(self.iface))
        if self.routes is None:
            self.routes = net.routes()

    def nexthop(self, ip):
        """Returns the MAC address for the next hop towards the given IP"""
        if ip in self.arpcache:
            return self.arpcache[ip]

        default = None
        via = None
        for route in self.routes:
            if route.default():
                default = route
            elif ip in route.dst:
                via = route.via
                break

        if via is None and default is not None:
            via = default.via

        if via is not None:
            return self.arpcache.get(str(via), None)
        return None

    def process(self, pkt):
        # Drop packets that don't include Ethernet and IP.
        if any(layer not in pkt for layer in (scapy.IP, scapy.Ether)):
            return

        # Drop packets for whom we are the intended L3 recipient.
        if pkt[scapy.IP].dst == self.ipaddr:
            return

        # Drop packets for which we are the L2 source or we are not the destination.
        if pkt[scapy.Ether].dst != self.hwaddr or pkt[scapy.Ether].src == self.hwaddr:
            return

        # Determine the MAC address for the local destination or next hop.
        hwdst = self.nexthop(pkt[scapy.IP].dst)
        if hwdst is None:
            logger.debug("Dropping packet %s > %s: next hop unknown", pkt[scapy.IP].src, pkt[scapy.IP].dst)
            return

        pkt = pkt.copy()
        pkt[scapy.Ether].dst = hwdst
        src, dst = pkt[scapy.IP].src, pkt[scapy.IP].dst

        # After having patched the dst MAC, but before patching the src, apply the filter
        if self.filter is not None:
            pkt = self.filter(pkt)

        if pkt is None:
            logger.debug("Dropping packet packet %s > %s: filter returned None", src, dst)
            return

        if pkt is not None:
            pkt[scapy.Ether].src = self.hwaddr
            clear_chksums(pkt) # TODO: investigate why this is needed, because it should not be (scapy bug?).
            scapy.sendp(pkt, iface=self.iface)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Forwarded %s > %s to %s: %s", pkt[scapy.IP].src, pkt[scapy.IP].dst, pkt[scapy.Ether].dst, base64.b64encode(scapy.raw(pkt)).decode())

def clear_chksums(pkt):
    """
    Deletes IP, UDP, and TCP checksums from pkt, such that they are recalculated by Scapy

    :param pkt: Packet for which to clear checksums.
    :type pkt: scapy.packet.Packet
    """
    for layer in (scapy.IP, scapy.UDP, scapy.TCP):
        if layer in pkt:
            del pkt[layer].chksum
