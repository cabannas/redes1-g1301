import struct
import binascii


def chksum(msg):
    """
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    """
    s = 0
    for i in range(0, len(msg), 2):
        if (i + 1) < len(msg):
            a = msg[i]
            b = msg[i + 1]
            s = s + (a + (b << 8))
        elif (i + 1) == len(msg):
            s += msg[i]
        else:
            raise Exception('Error calculando el checksum')
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s



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
protocol = 17
s_addr = 167772161
d_addr = 167772162


header = struct.pack(fmt_string,
                    version_ihl,
                    tos,
                    total_length,
                    identification,
                    flags_offset,
                    ttl,
                    protocol,
                    0,
                    s_addr,
                    d_addr)


checksum_calculated = socket.htons(chksum(header))
print('\nPaquete creado (checksum=0)')
print('Calculamos el checksum de la cabecera: ' + str(checksum_calculated))

ip_header = struct.pack(fmt_string,
                        version_ihl,
                        tos,
                        total_length,
                        identification,
                        flags_offset,
                        ttl,
                        protocol,
                        checksum_calculated,
                        s_addr,
                        d_addr)

print('\nEnviamos el paquete con el nuevo checksum calculado -> ...')



print('\n------------------------------------------------------------')



print('\n... -> Llega el paquete')


print('\nExtraemos el valor del checksum y lo guardamos en una variable temporal')
checksum_tmp = struct.unpack('!H', ip_header[10:12])[0]
print('Checksum temporal: ' + str(checksum_tmp))


print('\nCambiamos el valor que habia en el campo checksum de la cabecera a 0')
header = ip_header[0: 10] + struct.pack('!H', 0) + ip_header[12: 20]

print('\nVolvemos a calcular el checksum de la cabecera y lo comprobamos')
checksum_calculated = socket.htons(chksum(header))
print('checksum_calculated == checksum_tmp: ' + str(checksum_calculated == checksum_tmp) + '\n')
