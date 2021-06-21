#!/usr/bin/python3//declaramos la vercion de python 

import socket, sys #importamos el socket que nos da la libreria sniff, tambien importamos sys   
import textwrap #importamos la biblioteca textwrap
import binascii #importamos la biblioteca binescii
from struct import * #buscamos la libreria en toda la ubicacionn de python de 
from typing import Protocol #le indicamos de donde estamos importando 


try: #abrimos un try 
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) #guardamos en la variable s los sockets en el que usaremos las herramientas de la libreria socket
except: #abrimos la condicion except 
    print ('Socket no se pudo crear. Error de codigo : ' + str(msg[0]) + ' Message ' + msg[1]) #imprimimos un mensaje de error en el socket para luego mostrar en mensaje el error
    sys.exit() #cerramos la condicion except 

while True: #abrimos la condicion de while en verdadero 
    packet = s.recvfrom(65565) #creamos la variable packet en la que guardamos la variable s con la velocidad de recepcion de paquetes

    packet = packet[0] #inicializamos la variable con su respectivo vonstructor constructor en el vector 0


    ip_header = packet[0:20] #indicamos la cabeza del paquete que en la cabecera ip_header la hubicacion en el vector 

 
    iph = unpack('!BBHHHBBH4s4s' , ip_header) #iph nos ayda a desenpaquetar los paquetes del protocolo tcp 
   
    version_ihl = iph[0] #indicamos en un nuevo vector el tipo de protocolo que usaremos 
    version = version_ihl >> 4 #indicamos la vercion de tcp que es igual al 4 el cual generalmente se usa 
    ihl = version_ihl & 0xF #indicamos que la vvariable iph guardamos la version_ihl y añadimos 0xf el cual es un codigo exadecimal de phyton

    iph_length = ihl * 4 #miltiplicamos el tamaño de ihl x 4
    ttl = iph[5] #creamos una nueva variable tipo vector de tamaño 5 y reusamos la varible iph 
    protocol = iph[6] #de la misma manera se crea una nueva variable y reusamos iph 
    s_addr = socket.inet_ntoa(iph[8]); #guardamos en una nueva variable el socket en el le damos un tamaño y reusamos el vector iph con un nuevo tamaño 
    d_addr = socket.inet_ntoa(iph[9]); #guardamos en una nueva variable el socket en el le damos un tamaño y reusamos el vector iph con un nuevo tamaño

    print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)) #imprimos todas las variables antes mencionadas con para mostrar lo que se esta sniffiando 

    tcp_header = packet[iph_length:iph_length+20] #en la anterior cabecera tcp_header el vector iph_leng le suamamos 20 caracteres mas 

  
    tcph = unpack('!HHLLBBHHH' , tcp_header) #desenpaquetamos todo el paquete de que se intercepto 

    source_port = tcph[0] #damos lugar en el vector de cada paquete en este caso de que puerto salio
    dest_port = tcph[1] #de la misma manera se nis indica el puerto de destino
    sequence = tcph[2] # la sequencia del paquet 
    acknowledgement = tcph[3]  #nos indica el reconocimiento del paquete y le indicamos la pocicion en el vector
    doff_reserved = tcph[4] #nos indica el tamaño reservado para el paquete y le indicamos la pocicion en el vector 
    tcph_length = doff_reserved >> 4 #le indicamo el espacio en el vector 

    print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))# imprimos todas las variables antes mencionadas 

    h_size = iph_length + tcph_length * 4 #sumamos el tamaño de la variable tcph_length * 4 y lo sumamos con iph_length
    data_size = len(packet) - h_size#heredamos packet en len y lo restamos con la variable h_size para asignarlo a data_size

   
    data = packet[h_size:]# le asignamos a la variable data junto con todo el packet y el h_zise

    print ('Data : ' + str(data)) # imprimimos el mensaje data junto con la herencia de data
    print ()#imprimos un espacio 
    conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))#indicamos que en una nueva variable conn asemos uso de las herramientas de la libreira sockets para la obtencion de paquetes 

    filters = (["TCP", 6, "TCP"])#tratamos de identificar el pauete de tcp
    filter = []#declaramos un nueva variable vacia llamada filter

    if len(sys.argv) == 2: #abrimos un if el cual nos ayduara a filtrar los paquetes
        print("este es el filtro: ", sys.argv[1])#imprimimos el filtor segun al protocolo
        for f in filters:#abrimos un for el cual ira de uno en uno revisando los paquetes para ver el protocolo 
            if sys .argv[1] == f[0]:#abrimos un if el cual nos aydara a identificar el protocolo 
                filter = f #guardamos nuestro filtro 
    while True: # abrimos un while en verdadero 
        raw_data, addr = conn.recvfrom(65536) #usamos la herramienta de raw el en el cual inducaremos 
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)#buscamos la mac de donde se envio la maquina con la ayuda de la libreria raw 

        if eth_proto == 'IPV6': #tratamos de identificar si alguna pagina web al cual se esta enviando el paquete es ipv 6
            newPacket, nextProto = ipv6Header(data, filter) #identificamos el ipv6
            printPacketsV6(filter, nextProto, newPacket) #imprimos en tal caso exista el ipv6

        elif eth_proto == 'IPV4': #identificamos si existe un pauete al cual mandara un ipv4
            printPacketsV4(filter, data, raw_data) #imprimos y guardamos el ipv 4 de la pagina al cual va dirigido el paquete
def printPacketsV4(filter, data, raw_data): #definimos el la version en cual iomprimiremos el paquete  
    (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data) #creamos el vector y definimos en el cual se mostrara en el esniffer
    # TCP
    elif proto == 6 and (len(filter) == 0 or filter[1] == 6): #imrpimimos un elif el cual es como un else con una condicion de if en el cual diefernciaremos los protocolos de los paquetes 
        print("TCPv4") #imprimimos mensaje tcpv4
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl)) #de la misma manera identificamos e imprimimos el ttl
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target)) #de la misma manera imprimimos y identificamos el protocolo
        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24]) #imprimimos y desempaquetamos los paquetes 
        print('TCP Segment') #imprimos el mensaje de tcp segment 
        print('Source Port: {}\nDestination Port: {}'.format(src_port, dest_port)) #imprimimos el pueto de destino del paquete 
        print('Sequence: {}\nAcknowledgment: {}'.format(sequence, acknowledgment)) #imprimimos la sequencia del paquete 
        print('Flags') #imprimimos los flags (banderas del paquete)
        print('URG: {}\nACK: {}\nPSH: {}'.format(flag_urg, flag_ack, flag_psh)) #imprimimos los URG (en este caso si el pauete es urgente marcara un 1 y si no un 0)
        print('RST: {}\nSYN: {}\nFIN:{}'.format(flag_rst, flag_syn, flag_fin)) #de la misma menera vemos si el puerto en cuestion esta en escucha con el RST 

        if len(data) > 0: #abrimos un if 
            # HTTP 
            if src_port == 80 or dest_port == 80: #abrimos un if en el que indicamos el puerto el cual estara en escuha en este caso 80
                print('HTTP Dato') #imprimos el dato de http
                try: #condicion de si 
                    http = HTTP(data) #declaramos una nueva variable en este caso de si 
                    http_info = str(http.data).split('\n') #asemos un salto de consola y guardamos en http_ info  los datos de http 
                    for line in http_info: #abrimos un for el cual aremos un salto de espacion en espacio el la informacion del http (http_info)
                        print(str(line))#imprimimos la herencia de str en line 
                except: #condicion de except 
                    print(format_output_line("",data)) #imprimimos la variable format_output_line herencia con un espacio y el dato
            else:# condicion de else 
                print('TCP Dato') #imprimimos el mensaje tcp dato
                print(format_output_line("",data))#imprimimos la variable format_output_line herencia con un espacio y el dato
                print ()#imprimos un espacio 