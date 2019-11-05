# redes1-g1301


## Mininet

Antes de arrancar la herramienta Mininet, desconectamos primero la aplicación NetworkManager, ejecutando:
~~~
sudo systemctl stop network-manager
~~~

Para arrancar Mininet:
~~~
sudo mn --nat
~~~

Para salirse de la shell de Mininet:
~~~
quit
~~~

Para limpiar los recursos de Mininet una vez salido de la shell:
~~~
sudo mn -c
~~~

Para abrir una terminal en el host (por ejemplo, h1):
~~~
gterm h1
~~~


## Ejecucion de pruebas

En las terminales de h1 y h2 (hosts creados al arrancarse Mininet), ejecutamos:
~~~
-> Node h1:
python3 practica2.py --itf h1-eth0

-> Node h2:
python3 practica2.py --itf h2-eth0
~~~

Después, desde h1 insertamos la IP de h2 (habrá que mirarlo usando ifconfig: 10.0.0.2). Como resultado, debería devolver la dirección MAC asociada a esa IP, se puede comprobar usando ifconfig en la terminal de h2.

Inmediatamente, mostramos el contenido de la caché para comprobar si se ha almacenado correctamente la MAC resuelta.

Volvemos a realizar la solicitud y verificamos que no se ha realizado una petición ARP, ya que la dirección MAC se obtendrá directamente desde la caché. Nota: la caché se limpiará a los 10 segundos.


Realizamos otra prueba similar, configurando la IP de las dos interfaces para que sea la misma y como resultado, fallará el ARP gratuito al ejecutar el segundo script.
Para cambiar la IP de una interfaz (h2-eth0), ejecutamos:
~~~
sudo ifconfig h2-eth0 10.0.0.1 netmask 255.0.0.0 
~~~


## Entrega

Comprimir todo lo que se vaya a entregar en un zip cuyo formato es: practica2_1301_P11.zip

Archivos:
- arp.py
- ethernet.py
- leeme.txt
- practica2.py
- rc1_pcap.py