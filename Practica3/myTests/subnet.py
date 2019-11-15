
import netaddr
import pprint
import ipaddress

myIP = 3232282241
netmask = 4294967040

ip = ipaddress.IPv4Network(myIP)
print(ip)
print(ip.with_netmask)