from scapy.all import *
import Queue
import time
from threading import Thread
import sys
import threading 
import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


if os.getuid() != 0: # Valida si el script esta siendo corrido como root
    print("Debes ejecutar este script como root.")
    sys.exit(1)

# Las siguientes lineas definen los argumentos
parser = argparse.ArgumentParser(description='Esta herramienta es un chat encubierto (covert channel) tipo client-to-client que utiliza el protocolo SNMP para intercambiar la informacion a traves de los OID en los paquetes tipo get-request. Para su uso es necesario que obligatoriamente defina tanto la IP origen (-l) asi como la IP destino (-d), la comunidad (-c) sirve como autenticacion y debe ser igual en ambos extremos, por defecto el valor de la comunidad es public, tambien los mensajes se pueden cifrar (-e) utilizando AES y la llave tambien debe ser igual en ambos extremos.')
parser.add_argument('-d', action="store",dest='IP_DESTINO', help=' IP destino')
parser.add_argument('-c', action="store",dest='COMUNIDAD', help='Valor de la comunidad SNMP')
parser.add_argument('-p', action="store",dest='PUERTO_UDP', help='Puerto destino')
parser.add_argument('-l', action="store",dest='IP_LOCAL', help='IP local')
parser.add_argument('-e', action="store",dest='LLAVE', help='Llave (AES) para cifrar los mensajes')
args = parser.parse_args()

if len(sys.argv) == 1: # Obliga a mostrar el texto del 'help' sino hay argumentos ingresados.
 parser.print_help()
 sys.exit(1)

args = vars(args) # Convierte los argumentos en formato diccionario para facil manejo.



if args['PUERTO_UDP' ] == None :
 uport= 161 # Si no se ingresa el puerto, por defecto sera 161/UDP
else:
 uport= int(args['PUERTO_UDP'])


if args['COMUNIDAD'] == None :
 communi= "public" # Si no se ingresa la comunidad , por defecto sera public
else:
 communi= args['COMUNIDAD']


if args['LLAVE'] == None :
 llave= '' # si no especifica la llave los mensajes no se cifran
else:
 llave= args['LLAVE']


if args['IP_DESTINO'] == None :
 print "Ingrese la IP con la que se va comunicar" # En caso de que no ingrese la IP destino saldra este mensaje
 sys.exit()
else:
 peer = args['IP_DESTINO']


if args['IP_LOCAL'] == None :
 print "Ingrese su direccion ip" # En caso de que no ingrese la direccion IP local aparecera este mensaje
 sys.exit()
else:
 miip = args['IP_LOCAL']

#La siguiente clase define las funciones para cifrar y decifrar los mensajes con AES
class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)  # utiliza vector de inicializacion para que el ciphertext de dos mensajes iguales sean diferentes
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)) # el ciphertext estara codificado en base64

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s): # definicion del pad
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

# La siguiente funcion convierte el texto plano en un OID 
def convertir (mensaje, llave):
   if llave =='' :
    mensaje= mensaje

   else:
    crom=AESCipher(llave)
    mensaje=crom.encrypt(mensaje)

   if len(mensaje) > 128:
    print "es grande"

   oid ="1.3" # todos los oid enviados empiezan con 1.3
   for cont in range (0, len(mensaje)):
       des=str (ord(mensaje[cont]))
       oid = oid + "." + des
       je = len(mensaje) -1
       if cont == je:
        oid = oid + ".0" # todos los oid terminan en 0

   return oid


#esta funcion define el envio del paquete SNMP
def enviando (peer, communi, uport, oid ):
 p = IP(dst=args['IP_DESTINO'])/UDP(sport=RandShort(),dport=uport)/SNMP(community=communi,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
 send(p, verbose=0) 


# esta funcion define el prn del sniff de scapy
def snmp_values(llave):
          
    def sndr(pkt):
        eso=0
        a= " " 
        d= " "
        pl = pkt[SNMP].community.val
        od = str(pl)
        s = pkt[SNMPvarbind].oid.val
        l = str(s)
        long= len(l) + 1

       	if od == communi: 
 

         for i in range (4, len(l)):
	            if l[i] == ".":
                     e=chr(int(a))
                     d= d + e
             
                     a=" "
                    else: 
         	     b=l[i]
                     a= a + b
         if llave != '' :
           Re= AESCipher(llave)
           av= Re.decrypt(d)
           if av == "q":
              print " "
              print "My_friend abandono la sesion"
           else:
              print " "
              print "My_friend:" +  av

         else:
            if d == "q":
              print " "
              print "My_friend abandono la sesion"
            else: 
              print " "
              print "My_friend:" +  d


        else:
         print "La autenticacion fallo, verificque el valor de la comunidad" 
              
    return sndr   
    
        
                   
    
  
#esta funcion define el sniffer y los filtros necesarios para leer el paquete de entrada
def sniffer (puerto, peer, miip, llave): 
 filterstr= "udp and ip src " + peer +  " and port " +str(puerto)+ " and ip dst " +miip
 sniff(prn=snmp_values(llave), filter=filterstr, store=0, count=10)
 return

alias = raw_input("Ingrese su nombre:")
print " "
print "Digite 'q' cuando quiera abandonar el chat"
print "Presione Enter para empezar y cada vez que reciba un mensaje"
print " " 

message= raw_input(alias + " ->")

thread = Thread(target = sniffer, args = (uport,peer,miip,llave)) # craecion del thread para el  sniffer
thread.start()

while message!= 'q':

       message=raw_input(alias + "->")
       if message!='':
            oid=convertir(message,llave)
            enviando (peer, communi, uport,oid)
            time.sleep(0.2)

print"gracias por utilizar el programa :). Presiona Ctrl + Z"
sys.exit()

