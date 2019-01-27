# coding: utf-8
"""
Capture and manipulate traffic off the network.
"""
# Make snare functions availible from the base module.
from .arp import *
from .forward import *
from .sniffer import *
from .tcp import *
from . import net

# Prevent Scapy from direct printing verbose information.
import scapy.all as scapy
scapy.conf.verb = 0
