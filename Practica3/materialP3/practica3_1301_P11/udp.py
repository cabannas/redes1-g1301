from ip import *
import struct

UDP_HLEN = 8
UDP_PROTO = 17



def getUDPSourcePort():
    """
        Nombre: getUDPSourcePort
        Descripción: Esta función obtiene un puerto origen libre en la máquina actual.
        Argumentos:
            -Ninguno
        Retorno: Entero de 16 bits con el número de puerto origen disponible

    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portNum = s.getsockname()[1]
    s.close()
    return portNum



def process_UDP_datagram(us, header, data, srcIP):
    """
        Nombre: process_UDP_datagram
        Descripción: Esta función procesa un datagrama UDP. Esta función se ejecutará por cada datagrama IP que contenga
        un 17 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer los campos de la cabecera UDP
            -Loggear (usando logging.debug) los siguientes campos:
                -Puerto origen
                -Puerto destino
                -Datos contenidos en el datagrama UDP

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del datagrama UDP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno

    """
    logging.debug('Función implementada: process_UDP_datagram\n')

    datagram_header = struct.unpack('!HHHH', data[0: UDP_HLEN])
    srcPort     = datagram_header[0]
    dstPort     = datagram_header[1]
    data_octets = data[UDP_HLEN:]

    # Loggear campos
    logging.debug('------------------------------------------------')
    logging.debug('[UDP] DATAGRAM (%d bytes)' % (len(data)))
    logging.debug('* Puerto origen   : ' + str(srcPort))
    logging.debug('* Puerto destino  : ' + str(dstPort))
    logging.debug('* Datos contenidos: ' + str(data_octets))
    logging.debug('------------------------------------------------\n')
    return
    


def sendUDPDatagram(data, dstPort, dstIP):
    """
        Nombre: sendUDPDatagram
        Descripción: Esta función construye un datagrama UDP y lo envía
        Esta función debe realizar, al menos, las siguientes tareas:
            -Construir la cabecera UDP:
                -El puerto origen lo obtendremos llamando a getUDPSourcePort
                -El valor de checksum lo pondremos siempre a 0
            -Añadir los datos
            -Enviar el datagrama resultante llamando a sendIPDatagram

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el datagrama UDP
            -dstPort: entero de 16 bits que indica el número de puerto destino a usar
            -dstIP: entero de 32 bits con la IP destino del datagrama UDP
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no

    """
    logging.debug('Función implementada: sendUDPDatagram\n')
    datagram = bytes()

    srcPort = getUDPSourcePort()
    length  = UDP_HLEN + len(data)

    datagram += struct.pack('!HHHH',
                            srcPort,
                            dstPort,
                            length,
                            0)
    datagram += bytes(data)

    ret = sendIPDatagram(dstIP, datagram, UDP_PROTO)
    return ret



def initUDP():
    """
        Nombre: initUDP
        Descripción: Esta función inicializa el nivel UDP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_UDP_datagram con el valor de protocolo 17

        Argumentos:
            -Ninguno
        Retorno: Ninguno

    """
    logging.debug('Función implementada: initUDP\n')
    registerIPProtocol(process_UDP_datagram, UDP_PROTO)
    return
