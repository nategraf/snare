# coding: utf-8
import logging
import scapy.all as scapy
import signal
import threading

logger = logging.getLogger(__name__)

class StopSniffing(Exception):
    """StopSniffing may raised while processing a packet to indicate stop the sniffer."""

class Sniffer:
    """
    Sniffer is the core component of the traffic capture framework.

    This class uses the Scapy sniffer to collect packets off the wire. It then
    passes them to the modules for processing.

    :Example:

    >>> import snare
    ...
    >>> def show_pkt(pkt):
    ...     print(pkt.summary())
    ...     return pkt
    ...
    >>> sniffer = snare.Sniffer(
    ...     iface='tap0',
    ...     modules=[snare.ArpMitmModule(filter=show_pkt)]
    ... )
    ...
    >>> # Run the sniffer in background thread with:
    >>> # sniffer.start()
    >>> # Or run it blocking on the current thread with:
    >>> # sniffer.run()

    :param iface: Name of the interface to listen on.
    :type iface: str
    :param processor: Function to be called each time a packet is intercepted.
        The given packet is mutable.
    :type processor: function(scapy.Packet), optional
    :param store: Whether to store sniffed packets or discard them. If True, packets will be
        collected in the sniffer.packets field.
    :type store: bool, optional
    :param filter: pcap filter applied to the socket, such that only filtered packets will
        be processed. See `man pcap-filter` for more details on pcap filters.
    :type filter: str, optional
    :param quantum: Interval, in seconds, to stop the sniffer to check the stop event.
    :type quantum: float, optional
    :param modules: List of modules to launch the sniffer with.
    :type modules: list(Module), optional
    """
    def __init__(self, iface, processor=None, store=False, filter=None, quantum=0.25, modules=None):
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
        self._activemodules = []

        if modules is not None:
            self.register(*modules)

    def register(self, *mods):
        """Add new modules to the sniffer"""
        with self._moduleslock:
            self.modules.extend(mods)
            self._newmodules.extend(mods)

    def process(self, pkt):
        """Process the given packet through each active module, and ``self.processor``"""
        with self._moduleslock:
            for mod in self._activemodules:
                try:
                    mod.process(pkt)
                except StopSniffing:
                    self._stopevent.set()

        if self.processor is not None:
            try:
                self.processor(pkt)
            except StopSniffing:
                self._stopevent.set()

    def run(self):
        """Run the sniffer on the current thread, blocking until it terminates"""

        # If we are running on the main thread, install a handler for sigint.
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, self._sigint_handler)

        try:
            self._l2socket = scapy.conf.L2listen(iface=self.iface, filter=self.filter)

            while not self._stopevent.is_set():
                # Start any newly added modules.
                with self._moduleslock:
                    while self._newmodules:
                        mod = self._newmodules.pop()
                        mod.start(self)
                        self._activemodules.append(mod)

                # Sniff for one quantum, processing packets as we go.
                pkts = self._l2socket.sniff(timeout=self.quantum, prn=self.process, store=self.store)
                self.packets.extend(pkts)
        finally:
            # Stop all the active modules and close the sniffing socket.
            with self._moduleslock:
                while self._activemodules:
                    self._activemodules.pop().stop()

            if self._l2socket is not None:
                self._l2socket.close()
                self._l2socket = None

    def start(self):
        """Start the sniffer on a new background thread"""
        self._stopevent.clear()
        if self._thread is None or not self._thread.is_alive():
            with self._moduleslock:
                self._newmodules = list(self.modules)
                self._activemodules = list()
            self._thread = threading.Thread(target=self.run, daemon=True)
            self._thread.start()

    def stop(self):
        """Signal the sniffer to stop"""
        self._stopevent.set()

    def join(self):
        """Block until the sniffer thread has terminated"""
        if self._thread is not None:
            self._thread.join()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args, **kwargs):
        self.stop()

    def _sigint_handler(self, signum, frame):
        """
        Handler for ``SIGINT`` to install when running on the main thread.
        Used to avoid an issue with using scapy as a library where the system will not respond to
        ``SIGINT`` and so is hard to stop.
        """
        self.stop()

class Module:
    """
    Module provides functionalies on top of the sniffing platform.
    User defined modules should inherit from this class.
    """
    def start(self, sniffer):
        """
        Start when the sniffer starts or this module is added to a running sniffer.
        """

    def process(self, pkt):
        """
        Process will be called for every packet recieved by the sniffer.
        Process may raise StopSniffing to signal that the sniffer should terminate.
        """

    def stop(self):
        """
        Stop will be called when the sniffer stops.
        """
