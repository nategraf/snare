from . import addr
import re

_route_file_exp = re.compile(r'(?P<iface>\w+)\s+(?P<dst>[0-9A-F]+)\s+(?P<gw>[0-9A-F]+)\s+(?:\d+\s+){4}(?P<mask>[0-9A-F]+)')

class Route:
    def __init__(self, ip, mask, via=None, iface=None):
        if (via is None) == (iface is None):
            raise ValueError("exacty one of via and iface must be provided")

        self.dst = addr.IpNet(ip, mask)

        if via is not None:
            self.via = addr.Ip(via)
        else:
            self.via = None

        self.iface = iface

    def default(self):
        """Returns true if this is a default route (i.e. to 0.0.0.0/0)"""
        return self.dst.cidr() == '0.0.0.0/0'

    def __str__(self):
        return '{0!s} via {1!s}'.format(self.dst, self.via or self.iface)

    def __repr__(self):
        return '<{0}.{1} {2!s}>'.format(__name__, type(self).__name__, self)

def _parseword(word):
    return int.from_bytes(bytes.fromhex(word), byteorder='little')

def routes():
    """Retrieve routes from the system"""
    result = []
    with open('/proc/net/route', 'r') as file:
        for line in file:
            m = _route_file_exp.match(line)
            if m is None:
                continue
            dst = _parseword(m.group('dst'))
            mask = _parseword(m.group('mask'))
            gw = _parseword(m.group('gw'))
            iface = m.group('iface')

            if gw != 0:
                result.append(Route(dst, mask, via=gw))
            else:
                result.append(Route(dst, mask, iface=iface))

    return result
