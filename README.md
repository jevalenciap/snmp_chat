snmp_chat esta escrito en Python y es un chat encubierto (covert channel) tipo client-to-client que utiliza el protocolo SNMP para intercambiar la informacion a traves de los OID utilizados en los paquetes SNMP tipo get-request.
Esta herramienta es client-to-client ya que no utiliza un servidor intermedio para establecer la comunicación (garantizando mayor confidencialidad, ya que tu información no residira en un tercer sistema), ni usa sockets para el intercambio de la información (disminuyendo la superficie de ataque), tanto el envio envio como la recepción de paquetes esta basada en scapy, la recepcion se hace configurando la tarjeta de red en modo promiscuo y husmeando (sniffing) el trafico de interes que a esta le llega. Este tipo de comunicación poco convencional lo hace aun más dificil de detectar.
En esta comunicación el valor de la comunidad SNMP sirve como autenticación de los paquetes, en caso de que los paquetes lleguen con un valor diferente a el de la comunidad definida, aparecera un error de autenticación.
Para garantizar confidencialidad en la comunicación los mensajes se pueden cifrar utilizando AES, para eso es necesario especificar  la misma llave precompartida en los dos extremos.

Uso:
*Se debe correr el mismo script en los dos hosts que se desean comunicar.
*En la distribución Kali Linux funciona perfectamnete sin necesidad de instalar nada.
*Para que se pueda usar a traves de Internet debes de realizar un Destination NAT (IP publica ---- > IP privada) en tu router o firewall sobre el puerto UDP que escojas en la configuración.
*Ejemplo de uso:

python snmp_chat.py -l 192.168.2.56 -d 192.168.2.10 -c nopublic -e 6523hsga*% -p 171
