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
parser = argparse.ArgumentParser(description='Esta herramienta contruida con fi')
parser.add_argument('-d', action="store",dest='peer', help='La IP destin$')
parser.add_argument('-c', action="store",dest='community', help='La comunidad S$')
parser.add_argument('-p', action="store",dest='port', help='El puerto destino d$')
parser.add_argument('-l', action="store",dest='miip', help='Mi direccion IP')
parser.add_argument('-s', action="store",dest='llave', help='Llave de cifrado AES')
args = parser.parse_args()

if len(sys.argv) == 1: # Obliga a mostrar el texto del 'help' sino hay argumentos ingresados.
 parser.print_help()
 sys.exit(1)

args = vars(args) # Convierte los argumentos en formato diccionario para facil manejo.


#mensaje= args['mensaje']
def convertir (mensaje, llave):
   if llave =='' :
    mensaje= mensaje

   else:
    crom=AESCipher(llave)
    mensaje=crom.encrypt(mensaje)
    
   if len(mensaje) > 128:
    print "es grande"

   oid ="1.3"
   for cont in range (0, len(mensaje)):
       des=str (ord(mensaje[cont]))
       oid = oid + "." + des
       je = len(mensaje) -1
       if cont == je:
        oid = oid + ".0"
#       print oid
   return oid

if args['port' ] == None :
 uport= 161 # Si no se ingresa el puerto, por defecto sera 161/UDP
else:
 uport= int(args['port'])


if args['community'] == None :
 communi= "public" # Si no se ingresa la comunidad , por defecto sera public
else:
 communi= args['community']


if args['llave'] == None :
 llave= '' # Si no se ingresa la comunidad , por defecto sera public
else:
 llave= args['llave']


if args['peer'] == None :
 print "ingrese la IP con la que se va comunicar"
 sys.exit()
else:
 peer = args['peer']


if args['miip'] == None :
 print "ingrese su direccion ip"
 sys.exit()
else:
 miip = args['miip']


class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def enviando (peer, communi, uport, oid ):
 p = IP(dst=args['peer'])/UDP(sport=RandShort(),dport=uport)/SNMP(community=communi,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
 send(p, verbose=0) # Envia el paquete



def snmp_values(llave):
          
    def sndr(pkt):
#     print llave
#     if llave =='':
        eso=0
        a= " " 
        d= " "
        pl = pkt[SNMP].community.val
        od = str(pl)
        s = pkt[SNMPvarbind].oid.val
        l = str(s)
        long= len(l) + 1
#        print "*Comunidad: "+od
       	if od == communi: 
#         print "*Comunidad: "+od 
#         print "*OID: " +l
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
           print " "
           print "My_friend:" +  av
         else:
           print " "
           print "My_friend:" +  d

        else:
         print "La autenticacion fallo, verificque el valor de la comunidad" 
              
    return sndr   
    
        
                   
    
  

def sniffer (puerto, peer, miip, llave): 
 filterstr= "udp and ip src " + peer +  " and port " +str(puerto)+ " and ip dst " +miip
# print filterstr
# filterstr= "udp and ip dst 192.168.1.67 and ip src 192.168.1.70 and port " +str(puerto)
# filterstr= "udp and  port " +str(puerto)
 sniff(prn=snmp_values(llave), filter=filterstr, store=0, count=10)
 return

alias = raw_input("Name:")
message= raw_input(alias + " ->")

thread = Thread(target = sniffer, args = (uport,peer,miip,llave))
thread.start()

while message!= 'q':

       message=raw_input(alias + "->")
       if message!='':
#            print "enviado"
#            message=raw_input(alias + "->")
            oid=convertir(message,llave)
            enviando (peer, communi, uport,oid)
            time.sleep(0.2)

print"gracias por utilizar el programa :). Presiona Ctrl + Z"
sys.exit()

