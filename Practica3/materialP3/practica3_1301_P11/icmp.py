from ip import *
from threading import Lock
import struct

ICMP_PROTO = 1

ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

timeLock = Lock()
icmp_send_times = {}



def process_ICMP_message(us, header, data, srcIp):
    """
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP:
                -Si es distinto de 0 el checksum es incorrecto y se deja de procesar el mensaje
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno

    """
    logging.debug('Función implementada: process_ICMP_message\n')

    # Calculamos el checksum de ICMP:
    # Extraemos primero el valor del checksum y lo guardamos en una variable temporal
    checksum_tmp = struct.unpack('!H', data[2:4])[0]

    # Cambiamos el valor que habia en el campo checksum del mensaje a 0
    message_check_0 = bytes()
    message_check_0 += data[0:2] + struct.pack("!H", 0) + data[4:]

    # Calculamos el checksum y lo comprobamos
    checksum_calculated = socket.htons(chksum(message_check_0))
    
    if checksum_calculated != checksum_tmp:
        logging.error("[ICMP] Checksum incorrecto")
        logging.error('checksum_calculated: ' + str(checksum_calculated))
        logging.error('checksum_tmp       : ' + str(checksum_tmp) + '\n')
        return


    fmt_string = "!BBHHH"
    icmp_header_fields = struct.unpack(fmt_string, data[0:8])

    icmp_type       = icmp_header_fields[0]
    icmp_code       = icmp_header_fields[1]
    icmp_checksum   = icmp_header_fields[2]
    icmp_identifier = icmp_header_fields[3]
    icmp_seq_num    = icmp_header_fields[4]

    # Si el campo type no es ni ICMP_ECHO_REQUEST_TYPE ni ICMP_ECHO_REPLY_TYPE
    if icmp_type != ICMP_ECHO_REQUEST_TYPE and icmp_type != ICMP_ECHO_REPLY_TYPE:
        return

    # Loggear campos
    logging.debug('------------------------------------------------')
    logging.debug('[ICMP] MESSAGE (%d bytes)' % (len(data)))
    logging.debug('* Tipo  : ' + str(icmp_type))
    logging.debug('* Codigo: ' + str(icmp_code))
    logging.debug('------------------------------------------------\n')


    # Si el tipo es ICMP_ECHO_REQUEST_TYPE
    if icmp_type == ICMP_ECHO_REQUEST_TYPE:
        sendICMPMessage(data[8:], ICMP_ECHO_REPLY_TYPE, icmp_code, icmp_identifier, icmp_seq_num, srcIp)

    # Si el tipo es ICMP_ECHO_REPLY_TYPE
    elif icmp_type == ICMP_ECHO_REPLY_TYPE:
        
        tiempo_recepcion = header.ts.tv_sec + header.ts.tv_usec/1000000
        with timeLock:
            tiempo_envio = icmp_send_times[(srcIp + icmp_identifier + icmp_seq_num)]
        
        resultado = tiempo_recepcion - tiempo_envio        

        print('------------------------------------------------')
        print('[ICMP] RTT')
        print('* Tiempo de recepcion: ' + str(tiempo_recepcion))
        print('* Tiempo de envio    : ' + str(tiempo_envio))
        print('* Resultado          : ' + str(resultado))
        print('------------------------------------------------\n')

    return



def sendICMPMessage(data, type, code, icmp_id, icmp_seqnum, dstIP):
    """
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP

            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no

    """
    logging.debug('Función implementada: sendICMPMessage\n')

    message = bytes()
    message_check_0 = bytes()

    # Si el campo type no es ni ICMP_ECHO_REQUEST_TYPE ni ICMP_ECHO_REPLY_TYPE
    if type != ICMP_ECHO_REQUEST_TYPE and type != ICMP_ECHO_REPLY_TYPE:
        return False


    # Construir la cabecera ICMP con checksum = 0
    message_check_0 += struct.pack('!BBHHH', type, code, 0, icmp_id, icmp_seqnum)

    # Añadir los datos al mensaje ICMP
    message_check_0 += data

    # Comprobar que la longitud es par, si no añadimos un byte a 0 al final
    if len(message_check_0) % 2 != 0:
        message_check_0 += struct.pack('B', 0)


    # Calcular el checksum y añadirlo al mensaje donde corresponda
    check_sum_icmp = socket.htons(chksum(message_check_0))

    # Construir el mensaje definitivo con checksum calculado
    message += message_check_0[0:2] + struct.pack("!H", check_sum_icmp) + message_check_0[4:]


    # Si type es ICMP_ECHO_REQUEST_TYPE
    if type == ICMP_ECHO_REQUEST_TYPE:
        # Guardar el tiempo de envío en el diccionario icmp_send_times
        with timeLock:
            icmp_send_times[(dstIP + icmp_id + icmp_seqnum)] = time.time()


    # Llamar a sendIPDatagram para enviar el mensaje ICMP
    ret = sendIPDatagram(dstIP, message, ICMP_PROTO)
    return ret



def initICMP():
    """
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno

    """
    logging.debug('Función implementada: initICMP\n')
    registerIPProtocol(process_ICMP_message, ICMP_PROTO)
    return
