# coding: utf-8
import scapy.all as scapy
import threading
import logging

logger = logging.getLogger(__name__)

class Sniffer:
    """
    Sniffer is the core component of the traffic capture framework.

    This class uses the Scapy sniffer to collect packets off the wire. It then
    passes them to the modules for processing.
    """
    def __init__(self, iface=None, processor=None, store=False, filter=None, quantum=0.25):
        self.iface = iface
        self.processor = processor
        self.store = store
        self.quantum = quantum
        self.filter = filter

        self.modules = []
        self.packets = []

        self._thread = None
        self._l2socket = None
        self._stopevent = threading.Event()
        self._moduleslock = threading.RLock()
        self._newmodules = []

    def register(self, *mods):
        with self._moduleslock:
            self.modules.extend(mods)
            self._newmodules.extend(mods)

    def process(self, pkt):
        with self._moduleslock:
            for mod in self.modules:
                if mod not in self._newmodules:
                    mod.process(pkt)
        if self.processor is not None:
            self.processor(pkt)

    def run(self):
        try:
            self._l2socket = scapy.conf.L2listen(iface=self.iface, filter=self.filter)

            while not self._stopevent.is_set():
                with self._moduleslock:
                    while self._newmodules:
                        self._newmodules.pop().start(self)

                pkts = self._l2socket.sniff(timeout=self.quantum, prn=self.process, store=self.store)
                self.packets.extend(pkts)
        finally:
            with self._moduleslock:
                for mod in self.modules:
                    mod.stop()

            if self._l2socket is not None:
                self._l2socket.close()
                self._l2socket = None

    def start(self):
        self._stopevent.clear()
        if self._thread is None or not self._thread.is_alive():
            with self._moduleslock:
                self._newmodules = list(self.modules)
            self._thread = threading.Thread(target=self.run, daemon=True)
            self._thread.start()

    def join(self):
        if self._thread is not None:
            self._thread.join()

    def stop(self):
        self._stopevent.set()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args, **kwargs):
        self.stop()

class Module:
    """
    Module is the base for a packet sniffer module.
    Implementaions of Module provide a discrete functionality towards complex packet analysis and manipulation.
    """
    def start(self, sniffer):
        """
        Start will be called when the sniffer starts
        """
        pass

    def process(self, pkt):
        """
        Process will be called for every packet recieved by the sniffer
        """
        pass

    def stop(self):
        """
        Stop will be called when the sniffer stops
        """
        pass

