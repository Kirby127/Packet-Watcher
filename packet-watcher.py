#Packet sniffer in python for Linux
#Picks up only incoming TCP packet

import subprocess
import os
import socket, sys
from struct import *

#Create an INET, STREAMing socket. IPPROTO_TCP only watches TCP packets
try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

# receive a packet
while True:
        packet = s.recvfrom(65565)

        #packet string from tuple
        packet = packet[0]

        #take first 20 bytes of the ip packet
        ip_header = packet[0:20]

        #Unpacks the header into a tuple with the length of 10/Each section of the header is unpacked in...
	#different way based on the letter.
	#B = unsigned char, H = unsigned short, 4s = char[4]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

	#Need to use inetntoa to format the unpacked data into an ip address
	s_addr = socket.inet_ntoa(iph[8]);
	d_addr = socket.inet_ntoa(iph[9]);

	#Time to live
	ttl = iph[5]

	#Internet Protocol Number... needs to be swichted to actual protocol
	#Example... 6 = TCP
	protocol = iph[6]

	if protocol == 6:
		proto = "TCP"
	else:
		proto = "Interet Protocol Number = ", protocol

	print "Protocol -", proto
	print "Time to live -", ttl
	print "Source Address -", s_addr
	print "Destination Address -", d_addr
	print "END OF IP PACKET HEADER"

	print ""

	print "BEGINNING OF TCP PACKET HEADER"

	#Pulls the next 4 bytes after IP packet header
	tcp_header = packet[20:24]

	#Unpacks into 2 unsigned shorts
	tcph = unpack("!HH", tcp_header)

	#Souce port and destination port assignment
	source_port = tcph[0]
	dest_port = tcph[1]

	#Print information
	print "Source Port -", source_port
	print "Destination Port -", dest_port

	print "---------------------------------------------------------------------------"

	#Split packets into files by Layer 7 Protocols
	ports = {22 : "ssh", 80 : "http", 443 : "https"}
	
	#Using system module to enter variable information into log file
	x = 0
	while x < 500: 
		val = str(ports.get(x))
		if val != "None" and str(source_port) == str(x):
			os.system("echo "+s_addr+" >> "+val+".log")
		x = x + 1
