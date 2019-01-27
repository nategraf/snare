# coding: utf-8
"""
Network address functions
"""

import fcntl
import socket
import struct
import logging

logger = logging.getLogger(__name__)

# Dummy socket used for fcntl functions
_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

class AddrMeta(type):
    @property
    def maxvalue(cls):
        return (0x1 << (cls.bytelen * 8)) - 1

class Addr(metaclass=AddrMeta):
    bytelen = 0

    def __init__(self, addr):
        self._str = None
        self._int = None
        self._bytes = None

        if isinstance(addr, type(self)):
            self._str = addr._str
            self._bytes = addr._bytes
            self._int = addr._int
        elif isinstance(addr, str):
            self._str = addr
        elif isinstance(addr, int):
            self._int = addr
        elif isinstance(addr, bytes):
            if len(addr) == self.bytelen:
                self._bytes = addr
            else:
                self._str = addr.decode('utf-8')
        else:
            raise ValueError('Cannot create {!s} from {!s}'.format(type(self), type(addr)))

    # Operations
    def __and__(self, other):
        return type(self)(int(self) & int(other))

    def __or__(self, other):
        return type(self)(int(self) | int(other))

    def __xor__(self, other):
        return type(self)(int(self) ^ int(other))

    def __invert__(self):
        return type(self)(int(self) ^ self.maxvalue)

    # Conversions
    def __str__(self):
        if self._str is None:
            self._str = self.bytes_to_str(bytes(self))
        return self._str

    def __int__(self):
        return int.from_bytes(bytes(self), byteorder='big')

    def __bytes__(self):
        if self._bytes is None:
            if self._str is not None:
                self._bytes = self.str_to_bytes(self._str)
            elif self._int is not None:
                self._bytes = self._int.to_bytes(self.bytelen, byteorder='big')
        return self._bytes

    def __repr__(self):
        return '<{0}.{1} {2!s}>'.format(__name__, type(self).__name__, self)

class Ip(Addr):
    bytelen = 4

    @staticmethod
    def bytes_to_str(b):
        return socket.inet_ntoa(b)

    @staticmethod
    def str_to_bytes(s):
        return socket.inet_aton(s)

    def slash(self):
        x, i = int(self), 0
        while x & 0x1 == 0:
            x >>= 1
            i += 1
        return 32 - i

class Mac(Addr):
    bytelen = 6

    @staticmethod
    def bytes_to_str(b):
        return ':'.join('%02x' % byte for byte in b)

    @staticmethod
    def str_to_bytes(s):
        return bytes.fromhex(s.replace(':', ''))

def _ifctl(ifname, code):
    if isinstance(ifname, str):
        ifname = ifname.encode('utf-8')

    return fcntl.ioctl(
        _socket.fileno(),
        code,
        struct.pack('256s', ifname[:15])
    )

def ifaddr(ifname):
    return Ip(_ifctl(ifname, 0x8915)[20:24]) # SIOCGIFADDR

def ifmask(ifname):
    return Ip(_ifctl(ifname, 0x891b)[20:24]) # SIOCGIFNETMASK

def ifhwaddr(ifname):
    return Mac(_ifctl(ifname, 0x8927)[18:24]) # SIOCGIFHWADDR

def cidr(ip, mask):
    return "{!s}/{:d}".format(ip, mask.slash())

def parsecidr(ipnet):
    ipstr, maskstr = ipnet.split('/')
    ip = Ip(ipstr)
    mask = Ip(0xffffffff ^ ((0x00000001 << (32-int(maskstr)))-1))
    return ip, mask

def ifcidr(ifname):
    return cidr(ifaddr(ifname), ifmask(ifname))
