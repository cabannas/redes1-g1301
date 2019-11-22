import struct
import ipaddress

dstIP       = 167772162  #10.0.0.2
myIP        = 167772161  #10.0.0.1
myNetmask   = 4278190080 #255.0.0.0


print('\nUna forma de hacerlo:')

print('dstIP:       ' + str(dstIP))
print('myIP:        ' + str(myIP))
print('myNetmask:   ' + str(myNetmask))
print('dstIP&myNetmask == myIP&myNetmask: ' + str(dstIP&myNetmask == myIP&myNetmask))



dstIP       = ipaddress.ip_address(dstIP)
myIP        = ipaddress.ip_address(myIP)
myNetmask   = ipaddress.ip_address(myNetmask)

print('\n\nOtra forma:')

print('dstIP:       ' + str(dstIP))
print('myIP:        ' + str(myIP))
print('myNetmask:   ' + str(myNetmask))


net = ipaddress.ip_network(str(myIP) + '/' + str(myNetmask), strict=False)

print('\nsubnet:')
for i in range(0, 16):
    print(net[i])
print('...')

print('\n' + str(dstIP) + ' in ' + str(net) + ': ' + str(dstIP in net) + '\n')

