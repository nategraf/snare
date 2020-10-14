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

.. literalinclude:: ../example.py
   :language: python
