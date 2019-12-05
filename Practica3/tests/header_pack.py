import struct
import binascii

fmt_string = "!BBHHHBBHII"

#min= 20 bytes para IHL
IHL = 20
#version_ihl = version (4 bits) + ihl (4 bits)
version_ihl = 4 << 4 | int(IHL/4)

tos = 0

#total_length = cabecera + payload
total_length = 20 + 80

identification = 42

flags = 0

offset = 8
#flags_offset = flags (3 bits) + offset (13 bits)
flags_offset = 1 << 13 | int(offset/8)

ttl = 64
protocol = 6
checksum = 0xabcd
s_addr = 0x0a0b0c0d
d_addr = 0x01010101


ip_header = struct.pack(fmt_string,
                        version_ihl,
                        tos,
                        total_length,
                        identification,
                        flags_offset,
                        ttl,
                        protocol,
                        checksum,
                        s_addr,
                        d_addr)


print('\nPaquete:')
print(ip_header)

ip_header_fields = struct.unpack(fmt_string, ip_header)
print('\nCampos de la cabecera:')
print(ip_header_fields)

print('\ntotal_length: ' + str(ip_header_fields[2]))
print('\nLongitud: ' + str(len(ip_header)))

print()

ip_header_3_primeros_campos = struct.unpack('!BBH', ip_header[0: 4])
print(ip_header_3_primeros_campos)

if ip_header_3_primeros_campos[2] is 100:
    print('Valor correcto: ' + str(ip_header_3_primeros_campos[2]) + '\n')


ip_header_primer_campo_no = struct.unpack('!BHHHBBHII', ip_header[1:])
print(ip_header_primer_campo_no)

if ip_header_primer_campo_no[2] is 42:
    print('Valor correcto: ' + str(ip_header_primer_campo_no[2]) + '\n')


ip_header_campo_protocol = struct.unpack('B', ip_header[9: 10])
print(ip_header_campo_protocol)

if ip_header_campo_protocol[0] is 6:
    print('Valor correcto: ' + str(ip_header_campo_protocol[0]) + '\n')