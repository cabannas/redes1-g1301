import sys
import argparse
import struct
from argparse import RawTextHelpFormatter
import time
import logging
import socket

from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b

def getIP(interface):
    '''
        Nombre: getIP
        Descripción: Esta función obtiene la dirección IP asociada a una interfaz. Esta funció NO debe ser modificada
        Argumentos:
            -interface: nombre de la interfaz
        Retorno: Entero de 32 bits con la dirección IP de la interfaz
    '''
    global ip;s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]
    

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   

def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    global netmask;s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close();netmask=ip
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
	global dfw
	'''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''

	p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
	dfw = p.stdout.read().decode('utf-8')
	return struct.unpack('!I',socket.inet_aton(dfw))[0]




if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Envía datagramas UDP o mensajes ICMP con diferentes opciones',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--dstIP',dest='dstIP',default = False,help='Dirección IP destino')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	parser.add_argument('--addOptions', dest='addOptions', default=False, action='store_true',help='Añadir opciones a los datagranas IP')
	parser.add_argument('--dataFile',dest='dataFile',default = False,help='Fichero con datos a enviar')
	args = parser.parse_args()
	
	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.interface is False:
		logging.error('No se ha especificado interfaz')
		parser.print_help()
		sys.exit(-1)
	
	
	
	print()
	
	print('myIP: ' + str(getIP(args.interface)) + '\t------> ' + str(ip[0]) + '.' + str(ip[1]) + '.' + str(ip[2]) + '.' + str(ip[3]))
	
	print('MTU: ' + str(getMTU(args.interface)))
	
	print('Netmask: ' + str(getNetmask(args.interface)) + '\t------> ' + str(netmask[0]) + '.' + str(netmask[1]) + '.' + str(netmask[2]) + '.' + str(netmask[3]))
	
	print('DefaultGW: ' + str(getDefaultGW(args.interface)) + '\t------> ' + str(dfw))