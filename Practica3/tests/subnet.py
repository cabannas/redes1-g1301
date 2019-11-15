
import pprint
import ipaddress
import struct
import socket

myIP = '10.0.0.1'


print(ipaddress.ip_address(myIP))
print(ipaddress.ip_network(myIP))


r = ipaddress.ip_address(myIP) in ipaddress.ip_network(myIP)
print('ipaddress.ip_address(myIP) in ipaddress.ip_network(myIP): ' + str(r))
print()