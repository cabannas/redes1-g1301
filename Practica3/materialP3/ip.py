import struct
import logging

from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
from threading import Lock

import math
import sys

# Semáforo global
globalLock = Lock()

SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b

# Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
# por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols = {}
# Valor inicial para el IPID
IPID = 0
# Valor de ToS por defecto
DEFAULT_TOS = 0
# Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
# Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
# Valor de TTL por defecto
DEFAULT_TTL = 64


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


def getMTU(interface):
    """
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    """
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s, SIOCGIFMTU, ifr))[1]

    s.close()

    return mtu


def getNetmask(interface):
    """
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I', ip)[0]


def getDefaultGW(interface):
    """
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    """
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    return struct.unpack('!I', socket.inet_aton(dfw))[0]


def process_IP_datagram(us, header, data, srcMac):
    """
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum sobre los bytes de la cabecera IP
                    -Comprobar que el resultado del checksum es 0. Si es distinto el datagrama se deja de procesar
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón
                    pasando los datos (payload) contenidos en el datagrama IP.

        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    """
    logging.debug('Función implementada: process_IP_datagram\n')
    
    # Definimos el formato
    fmt_string = '!BBHHHBBHII'

    # Extraer los campos de la cabecera IP
    ip_header = data[0: IP_MIN_HLEN]
    ip_header_fields = struct.unpack(fmt_string, ip_header)
    logging.debug('ip_header_fields: ' + str(ip_header_fields) + '\n')

    
    # Calcular el checksum
    # Extraemos primero el valor del checksum y lo guardamos en una variable temporal
    checksum_tmp = struct.unpack('!H', ip_header[10: 12])[0]

    # Version e IHL 
    version_ihl = ip_header_fields[0]
    version = version_ihl >> 4
    IHL = version_ihl - (version * 2 ** 4)
    IHL = IHL * 4  # IHL esta expresada en palabras de 4 bytes, hay que multiplicarlo por 4
    

    # Cambiamos el valor que habia en el campo checksum de la cabecera a 0
    h = data[0: 10] + struct.pack('!H', 0) + data[12: IHL]

    # Volvemos a calcular el checksum de la cabecera y lo comprobamos
    checksum_calculated = chksum(h)
    if checksum_calculated != checksum_tmp:
        print('Error de checksum')
        return


    # Analizar bits de MF y offset
    flags_offset = ip_header_fields[4]
    flags = flags_offset >> 13
    offset = flags_offset - (flags * 2 ** 13)
    offset = offset * 8  # Offset esta expresada en palabras de 8 bytes, hay que multiplicarlo por 8


    if not offset == 0:
        print('Error de offset')
        return

    srcIP = ip_header_fields[8]
    protocol = ip_header_fields[6]
    
    # Loggear campos
    logging.debug('----------------------')
    logging.debug('[IP DATAGRAM]\n')
    logging.debug('* IHL        : ' + str(IHL))
    logging.debug('* IPID       : ' + str(ip_header_fields[3]))
    logging.debug('* Flags      : ' + str(flags))
    logging.debug('* Offset     : ' + str(offset))
    logging.debug('* IP origen  : ' + str())
    logging.debug('* IP destino : ' + str(ip_header_fields[9]))
    logging.debug('* Protocolo  : ' + str(protocol))
    logging.debug('----------------------\n')
    

    # Comprobar funcion callback
    if str(protocol) in protocols:

        callback_fun = protocols.get(str(protocol))
        if callback_fun is None:
            logging.error('Error callbackFun')
            return

        # Llamamos a la funcion de nivel superior
        logging.debug('callback_fun: ' + str(callback_fun))
        callback_fun(us, header, data[IHL: ], srcIP)


def registerIPProtocol(callback, protocol):
    """
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla
            (diccionario) de protocolos de nivel superior dicha asociación.
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra
            llamada process_ICMP_message asocaida al valor de protocolo 1.
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado.
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno
    """
    protocols[str(protocol)] = callback


def initIP(interface, opts=None):
    global myIP, MTU, netmask, defaultGW, ipOpts
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    logging.debug('Función implementada: initIP\n')

    # Llamamos a initARP
    if initARP(interface) is False:
        return False

    # Obtenemos los siguientes datos usando un semaforo
    with globalLock:
        myIP = getIP(interface)
        MTU = getMTU(interface)
        netmask = getNetmask(interface)
        defaultGW = getDefaultGW(interface)

        # Almacenamos el valor de pts en la variable global ipOpts
        ipOpts = opts

    # Registrar a nivel Ethernet la funcion process_IP_datagram con Ethertype 0x0800
    registerCallback(process_IP_datagram, '0x0800')

    return True


def sendIPDatagram(dstIP, data, protocol):
    global IPID
    global myIP, MTU, netmask, defaultGW, ipOpts
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera en la posición correcta
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas:
                    -Si la dirección IP destino está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada a dstIP y usar dicha MAC
                    -Si la dirección IP destino NO está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada al gateway por defecto y usar dicha MAC
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
    logging.debug('Función implementada: sendIPDatagram\n')
    header = bytes()

    # Valores iniciales
    IHL = IP_MIN_HLEN  # Longitud basica de la cabecera
    fragmentar = False
    payload = 0
    cantidadMax = 0
    numFragm = 1
    totalDatos = len(data)

    # Si existen opciones, sumamos la longitud del campo "opcion" a la cabecera IP
    if ipOpts is not None:
        IHL += len(ipOpts)

    if IHL > IP_MAX_HLEN:
        return False

    # Longitud total del datagrama IP (cabecera + payload)
    datagramLength = IHL + totalDatos

    logging.debug('ipOpts: ' + str(ipOpts))
    logging.debug('datagramLength: ' + str(datagramLength))
    logging.debug('MTU: ' + str(MTU))


    if datagramLength > MTU:
        fragmentar = True

        # Cantidad de datos que podemos guardar en cada fragmento
        cantidadMax = MTU - IHL

        # Si la cantidad maxima no es multiplo de 8, cogemos un valor mas cercano a esa cantidad por abajo
        if cantidadMax % 8 != 0:
            cantidadMax = cantidadMax - (cantidadMax % 8)

        # Calculamos el numero de fragmentos que vamos a necesitar
        # math.ceil() nos permite redondear un numero hacia arriba, ejemplo: math.ceil(1.1) = 2
        numFragm = math.ceil(totalDatos / cantidadMax)


    logging.debug('fragmentar: ' + str(fragmentar))
    logging.debug('cantidadMax: ' + str(cantidadMax))
    logging.debug('numFragm: ' + str(numFragm) + '\n')


    for i in range(0, numFragm):

        # Version (4 bits) (valor=4)
        # IHL (4 bits) (min=20 bytes, max=60 bytes) (hay que expresarlo en palabras de 4 bytes)
        # Type of Service (1 byte) (valor=0)
        # Total Length (2 bytes) (cabecera + payload)
        # Identification (2 bytes) (IPID)
        # Flags(3 bits)
        # Offset (13 bits) (hay que expresarlo en palabras de 8 bytes)
        # Time to Live (1 byte) (valor=64)
        # Protocol (1 byte) (ICMP=1, TCP=16, UDP=17)
        # Header Checksum (2 bytes)
        # Direccion IP origen (4 bytes)
        # Direccion IP destino (4 bytes)
        # Opciones (tam variable) (min=0 bytes, max=40 bytes) (multiplo 4 bytes)

        # Juntamos los campos 'version' e 'ihl'
        version_ihl = 4 << 4 | int(IHL / 4)

        # Calculamos la cantidad de datos para cada fragmento
        if fragmentar is True:
            # Para el ultimo fragmento, calculamos los datos que nos quedan por enviar
            if i + 1 == numFragm:
                payload = totalDatos - (cantidadMax * i)
            else:
                payload = cantidadMax

            totalLength = IHL + payload

        else:
            totalLength = datagramLength

        # Juntamos los campos 'flags' y 'offset'
        MF = 1
        if i + 1 == numFragm:
            MF = 0
        offset = cantidadMax * i
        flags_offset = MF << 13 | int(offset / 8)

        logging.debug('--------------------------')
        logging.debug('[IP HEADER]\n')
        logging.debug('* version_ihl  : ' + str(version_ihl))
        logging.debug('* tos          : ' + str(DEFAULT_TOS))
        logging.debug('* totalLength  : ' + str(totalLength))
        logging.debug('* id           : ' + str(IPID))
        logging.debug('* flags_offset : ' + str(flags_offset))
        logging.debug('* ttl          : ' + str(DEFAULT_TTL))
        logging.debug('* protocol     : ' + str(protocol))
        logging.debug('* checksum     : ' + str(0))
        logging.debug('* myIP         : ' + str(myIP))
        logging.debug('* dstIP        : ' + str(dstIP))
        logging.debug('--------------------------\n')

        # Definimos el formato
        fmt_string = '!BBHHHBBHII'
        # Construimos la cabecera con el checksum=0, ese valor lo calcularemos mas tarde
        header += struct.pack(fmt_string,
                              version_ihl,
                              DEFAULT_TOS,
                              totalLength,
                              IPID,
                              flags_offset,
                              DEFAULT_TTL,
                              protocol,
                              0,
                              myIP,
                              dstIP)


        logging.debug('IP HEADER (checksum = 0):')
        logging.debug(str(header) + '\n')
        
        # Si existen opciones, lo añadiremos
        if ipOpts is not None:
            header += struct.pack('%ds' % (len(ipOpts)), bytes(ipOpts))

        # Calculamos el checksum
        checksum = chksum(header)

        # Creamos la cabecera definitiva, con el checksum calculado
        h = header[0: 10] + struct.pack('!H', checksum) + header[12: IP_MIN_HLEN]
        
        if ipOpts is not None:
            h += header[IP_MIN_HLEN: IP_MIN_HLEN + len(ipOpts)]


        logging.debug('IP HEADER (checksum = %d):' % (checksum))
        logging.debug(str(h) + '\n')
        
        logging.debug('IP DATA:')
        logging.debug(str(data) + '\n')


        # Creamos el fragmento/datagrama
        if fragmentar is True:
            fragment = h + data[offset: offset + payload]
            logging.debug('IP FRAGMENT:')
            logging.debug(str(fragment) + '\n')
        else:
            datagram = h + data
            logging.debug('IP DATAGRAM:')
            logging.debug(str(datagram) + '\n')


        # Si la direccion IP destino esta en mi subred, enviamos una peticion ARP para obtener la MAC asociada a esa IP
        if dstIP & netmask == myIP & netmask:
            logging.debug('ARPResolution(dstIP)')
            dstMac = ARPResolution(dstIP)
        else:
            logging.debug('ARPResolution(defaultGW)')
            dstMac = ARPResolution(defaultGW)


        logging.debug('dstMac: ' + str(dstMac) + '\t------> ' + str(dstMac.hex()) + '\n')

        # Enviamos el fragmento/datagrama
        if fragmentar is True:
            ret = sendEthernetFrame(data=fragment, len=totalLength, etherType=0x0800, dstMac=dstMac)
            if ret == -1:
                return False
        else:
            ret = sendEthernetFrame(data=datagram, len=totalLength, etherType=0x0800, dstMac=dstMac)
            if ret == -1:
                return False

    # Incrementamos la ID para la datagrama
    IPID += 1
    return True
