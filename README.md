ipasn lookup server
===================

[ipasn](https://github.com/CIRCL/IP-ASN-history/) lookup server is a whois server which give historical view on the association between IP addresses and ASN number. 

You need [ipasn](https://github.com/CIRCL/IP-ASN-history/) installed on your system in order to use this server.

ipasn lookup server objective is to provide a similar services than Cymru ip asn
service but with the complete historical view on an IP address.

Requirements
------------

- Python 2
- [ipasn_redis](https://pypi.python.org/pypi/ipasn-redis)

Usage
-----

        usage: server.py [-h] [-v] [-l] [-b B] [-p P]

        Whois server for ipasn history

        optional arguments:
          -h, --help  show this help message and exit
          -v          DEBUG logs activated
          -l          Log queries along with source IP address and TCP port
          -b B        Binding address (default: 0.0.0.0)
          -p P        TCP port (default: 4343)

