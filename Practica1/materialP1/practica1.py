'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''

from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

import datetime


ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30 * 60


def signal_handler(nsignal, frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)


def procesa_paquete(us, header, data):
	global num_paquete, pdumper

	logging.info('Nuevo paquete de {} bytes capturado a las {}.{}'.format(
	    header.len, header.ts.tv_sec, header.ts.tv_usec))
	num_paquete += 1

	# TODO imprimir los N primeros bytes
	N = args.nbytes

	if N < header.len:
		print('Los %d primeros bytes del paquete no.%d:' % (N, num_paquete))

	elif N == header.len:
		print('Los bytes del paquete capturado coinciden con el parámetro --nbytes')
		print('Los %d bytes del paquete no.%d:' % (N, num_paquete))

	else:
		N = header.len
		print('No hay suficientes bytes para imprimir (--nbytes = %d)' % (args.nbytes))
		print('Los %d bytes del paquete no.%d:' % (N, num_paquete))

	d = data[0: N]

	# NOTA: calculamos el numero de lineas que se van a necesitar (cada linea va a ocupar como mucho 16 bytes)
	lineas = int(len(d) / 16) + 1

	for i in range(0, lineas):
		# NOTA: coge los bytes de 16 en 16
		l = d[16 * i: 16 * (i + 1)]

		# NOTA: bytes del paquete capturado expresados en hexadecimal, con 2 digitos por Byte (separados por espacios en blanco)
		print('\t' + ' '.join(['{:02x}'.format(b) for b in l]))

	print('\n')

	# NOTA: modificamos la fecha del paquete capturado, sumandole 30 min (30*60 segundos)
	header.ts.tv_sec += TIME_OFFSET

	# Escribir el tráfico al fichero de captura con el offset temporal
	if args.interface:
		pcap_dump(pdumper, header, data)


if __name__ == "__main__":
	global pdumper, args, handle
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile',
	                    default=False, help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface',
	                    default=False, help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int,
	                    default=14, help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False,
	                    action='store_true', help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level=logging.DEBUG,
		                    format='[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level=logging.INFO,
		                    format='[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	pdumper = None
	descr2 = None

	# TODO abrir la interfaz especificada para captura o la traza

	if args.interface:
		handle = pcap_open_live(args.interface, ETH_FRAME_MAX,
		                        NO_PROMISC, TO_MS, errbuf)
		if handle is None:
			logging.error('Error al abrir interfaz')

	elif args.tracefile:
		handle = pcap_open_offline(args.tracefile, errbuf)
		if handle is None:
			logging.error('Error al abrir traza')

	# TODO abrir un dumper para volcar el tráfico (si se ha especificado interfaz)

	if args.interface:
		descr2 = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)
		if descr2 is None:
			logging.error('Error al abrir descriptor de archivo pcap')

		fname = 'captura.' + args.interface + '.' + str(int(time.time())) + '.pcap'

		pdumper = pcap_dump_open(descr2, fname)
		if pdumper is None:
			logging.error('Error al crear objeto dumper para guardar los paquetes')

	ts = time.time()
	print('Tiempo actual UNIX en segundos: ' + str(ts))
	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
	print('Fecha actual: ' + str(st) + '\n\n')

	ret = pcap_loop(handle, 50, procesa_paquete, None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))

	# TODO si se ha creado un dumper cerrarlo
	pcap_close(handle)
	
	if args.interface:
		pcap_dump_close(pdumper)
		pcap_close(descr2)

	# if args.interface:
	# 	pcap_dump_close(pdumper)
	# 	pcap_close(descr2)
	# 	pcap_close(handle)
    #
	# elif args.tracefile:
	# 	pcap_close(handle)
