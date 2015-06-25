#!/usr/bin/python

import socket
import os
import struct
import binascii
import string

global proto_TCP
global proto_ICMP
global proto_UDP

proto_TCP = 6
proto_ICMP = 1
proto_UDP = 17

def analyze_ICMP_header(data):
	icmp_hdr 		= struct.unpack("!2H", data[:4])
	icmp_type 		= icmp_hdr[0] >> 8
	icmp_code 		= icmp_hdr[0] & 0xff
	icmp_chksum		= icmp_hdr[1]
	icmp_redirect	= False
	icmp_echo 		= False
	icmp_echo_reply	= False
	#net_unreachable, host_unreachable, protocol_unreachable, port_unreachable, frag_needed_DF_set, src_route_failed = False
	#time_to_live, frag_reassembly_time = False
	
	print "+================ ICMP HEADER ==================+"
	print "ICMP Type:\t\t%hu" % icmp_type
	print "ICMP Code:\t\t%hu" % icmp_code
	
	if icmp_type == 5:
		icmp_hdr2		= struct.unpack("!I", data[4:8])
		icmp_gateway	= socket.inet_ntoa(icmp_hdr2[0])
		print "ICMP Redirect Gateway:\t%s" % icmp_gateway
		
		if icmp_code == 0:
			print "\t[*] Redirect datagrams for Network"
		elif icmp_code == 1:
			print "\t[*] Redirect datagrams for Host"
		elif icmp_code == 2:
			print "\t[*] Redirect datagrams for Type of Service and Network"
		elif icmp_code == 3:
			print "\t[*] Redirect datagrams for Type of Service and Host"
		else:
			print "\t[-] Invalid Redirect Code."

	
	elif icmp_type == 8:
		icmp_echo 	= True
		icmp_hdr2	= struct.unpack("!2H", data[4:8])
		icmp_id		= icmp_hdr2[0]
		icmp_seq	= icmp_hdr2[1]
		print "ICMP Echo:\t\t%s" % icmp_echo
		print "ICMP ID #:\t\t%hu" % icmp_id
		print "ICMP Sequence #:\t%hu" % icmp_seq
	
	elif icmp_type == 0:
		icmp_echo_reply = True
		icmp_hdr2	= struct.unpack("!2H", data[4:8])
		icmp_id		= icmp_hdr2[0]
		icmp_seq	= icmp_hdr2[1]
		print "ICMP Echo Reply:\t%s" % icmp_echo_reply
		print "ICMP ID #:\t\t%hu" % icmp_id
		print "ICMP Sequence #:\t%hu" % icmp_seq
	
	elif icmp_type == 3:
		print "[*] ICMP Destination Unreachable"
		if icmp_code == 0:
			print "\t[*] Network Unreachable"
		elif icmp_code == 1:
			print "\t[*] Host Unreachable"
		elif icmp_code == 2:
			print "\t[*] Protocol Unreachable"
		elif icmp_code == 3:
			print "\t[*] Port Unreachable"
		elif icmp_code == 4:
			print "\t[*] Fragment Needed, Do Not Fragment Set"
		elif icmp_code == 5:
			print "\t[*] Source Route Failed"
		else:
			print "[-] ICMP Code Invalid."
			
		return data[4:]
	
	elif icmp_type == 11:
		print "[*] Packet Time Exceeded"
		if icmp_code == 0:
			print "\t[*] Time To Live Exceeded"
		elif icmp_code == 1:
			print "\t[*] Fragment Reassembly Time Exceeded"
		else:
			print "[-] ICMP Code Invalid."
		
		return data[4:]
	
	else:
		print "[*] ICMP Type Other/Invalid."
	
	return data[8:]

def analyze_TCP_header(data):
	# The struct here unpacks everything (from the network - "data") into a tuple, the values are then sliced and diced into nice neat easy to digest packages with bit operations
	# 2H = 2x 2 bytes for Source port and Dest port, 
	# 2I = 2x 4 bytes for Seq Number and Ack Number, 
	# 4H = data offset (4 bits), Reserved (6 bits), 6 FLAGS (1 bit per flag), Window (2 bytes), Checksum (2 bytes), Urgent pointer (2 bytes, from URG flag)
	
	tcp_hdr 	= struct.unpack("!2H2I4H", data[:20]) 
	src_port 	= tcp_hdr[0]					# 2 bytes
	dst_port 	= tcp_hdr[1]					# 2 bytes
	seq_num 	= tcp_hdr[2]					# 4 bytes
	ack_num		= tcp_hdr[3]					# 4 bytes
	data_offset = tcp_hdr[4] >> 12				# shift right by 12 bits, we need the first four bits
	reserved 	= (tcp_hdr[4] >> 6) & 0x3f 		# shift right 6 bits, leaving with 12 bits, then mask at 00111111 (total of 6 bits)...
												# reserved is 4 bits inside, 6 bits for reserved, then six bits for flags after
	# Flags...
	urg_flag 	= (tcp_hdr[4] >> 5) & 0x1		# Urgent flag is at bit 10
	ack_flag	= (tcp_hdr[4] >> 4) & 0x1		# Ack flag is at bit 11
	psh_flag	= (tcp_hdr[4] >> 3) & 0x1		# Push flag is at bit 12
	rst_flag	= (tcp_hdr[4] >> 2) & 0x1		# Reset flag is at bit 13
	syn_flag	= (tcp_hdr[4] >> 1) & 0x1		# Synchronize flag is at bit 14
	fin_flag	= tcp_hdr[4] & 0x1				# Finish flag is at bit 15
	tcp_window	= tcp_hdr[5]					# 2 bytes
	chk_sum		= tcp_hdr[6]					# 2 bytes
	urg_ptr		= tcp_hdr[7]					# 2 bytes
	
	print "+================ TCP HEADER ================+"
	print "Source Port:\t\t%hu" % src_port
	print "Destination Port:\t%hu" % dst_port
	print "Sequence Number:\t%u" % seq_num
	print "Ack Number:\t\t%u" % ack_num
	print "Data Offset:\t\t%hu" % data_offset
	print "Reserved:\t\t%hu" % reserved
	print "Flags:"
	print "\tURG:\t\t%hu" % urg_flag
	print "\tACK:\t\t%hu" % ack_flag
	print "\tPSH:\t\t%hu" % psh_flag
	print "\tRST:\t\t%hu" % rst_flag
	print "\tSYN:\t\t%hu" % syn_flag
	print "\tFIN:\t\t%hu" % fin_flag
	print
	print "TCP Window:\t\t%hu" % tcp_window
	print "Checksum:\t\t%hu" % chk_sum
	print "Urgent Pointer:\t\t%hu" % urg_ptr
	print 
	
	
	data = data[20:]
	
	return data
	
def analyze_UDP_header(data):
	
	# UDP header is simple, 4x 2 byte fields, source port, destination port, length, and checksum...done.
	udp_hdr = struct.unpack("!4H", data[:8])
	src_port 	= udp_hdr[0]
	dst_port 	= udp_hdr[1]
	length		= udp_hdr[2]
	chk_sum		= udp_hdr[3]
	
	# Make a pretty table
	print "+===============UDP HEADER================+"
	print "Source Port:\t\t%hu" % src_port
	print "Destination Port: \t%hu" % dst_port
	print "Length:\t\t\t%hu" % length
	print "Checksum:\t\t%hu" % chk_sum
	print
	print 
	
	data = data[8:]	
	
	return data
	

def analyze_IP_header(data):
	
	# The struct here unpacks everything (from the network - "data") into a tuple, the values are then sliced and diced into nice neat easy to digest packages with bit operations
	IPheader = struct.unpack("!6H4s4s", data[:20]) # 20 bytes total - 6H = 6x 2 byte unsigned short, 4s = 4x 4 byte string
	# IPheader = struct.unpack("!6H4s4sI", data[:24]) # adding options and padding, as a 4 byte unsigned int
	
	# byte 1-2
	ver = IPheader[0] >> 12				# Version is first 4 bits of this 2 byte array...Take all 16 bits, shift right by 12 bits, leaves version all the way to the right, leave all zeros on the left...this let's us see only the data we want to see. 
	IHL = (IPheader[0] >> 8) & 0x0f 	# 00001111 -> IHL is 2nd 4 bits of first 2 bytes...shift IHL all the way to the end, then the 00001111 leaves us with only the bits we want for the IHL
	TOS = IPheader[0] & 0x00ff		# 0000000011111111...Type of service is last byte of the two byte field...moves TOS to the end, then only keeps the last byte of the array
	
	# byte 3-4
	total_Length = IPheader[1] 			# Total Length is a 2 byte field, unpacked into a 2 byte unsigned short
	
	# byte 5-6
	IP_id = IPheader[2]					# Identification is a 2 byte field
	
	# byte 7-8
	flags = IPheader[3] >> 13			# Same as version above, flags is a 3 bit field
	frag_offset = IPheader[3] & 0x1fff	# 0000111111111111 -> fragment offset is last 12 bits of this two byte field
	
	# byte 9-10
	IP_ttl = IPheader[4] >> 8			# Time to live is first byte of next 2 byte field unpacked
	proto = IPheader[4] & 0x00ff		# Protocol is last byte of this 2 byte field
	
	# byte 11-12
	header_checksum = IPheader[5]		# Header Checksum is full 2bytes of 2 byte field
	
	# 1st 4s in the struct
	source_IP = socket.inet_ntoa(IPheader[6])	# Source IP address is full 4 bytes, this converts it from network to ascii
	
	# 2nd 4s in the struct
	dest_IP = socket.inet_ntoa(IPheader[7])		# Destination IP address is full 4 bytes as well, see above
	
	# implement later, not too hard...
	# options = IPheader[8] >> 8			# IP options go here, first 3 bytes of this 4 byte header ending, so shift everything to the right by 8 bits so that they end up on the end.
	# Padding = IPheader[8] & 0x0000000f	# IP padding is at end of the 4 byte field
	
	
	
	# Make a pretty table
	print "+=============IP HEADER=============+"	
	print "Version:\t\t%hu" % ver
	print "IHL:\t\t\t%hu" % IHL
	print "Type of Service:\t%hu" % TOS
	print "Total Length:\t\t%hu" % total_Length
	print "ID:\t\t\t%hu" % IP_id
	print "Flags:\t\t\t%hu" % flags
	print "Fragmentation Offset:\t%hu" % frag_offset
	print "TTL:\t\t\t%hu" % IP_ttl
	if (proto == proto_TCP):
		next_proto = "TCP"
		print "Protocol:\t\t%s" % next_proto
	elif (proto == proto_ICMP):
		next_proto = "ICMP"
		print "Protocol:\t\t%s" % next_proto	
	elif (proto == proto_UDP):
		next_proto = "UDP"
		print "Protocol:\t\t%s" % next_proto
	else:
		print "Protocol:\t\t**OTHER**"
	print "Checksum:\t\t%hu" %header_checksum
	print "Source IP:\t\t%s" % source_IP
	print "Destination IP:\t\t%s" % dest_IP
	print
	print
		
	data = data[20:]
	return data, next_proto

def analyze_ether_header(data):
	eth_hdr 	= struct.unpack('!6s6sH', data[:14])	#IPv4 = 0x0800
	dest_mac 	= binascii.hexlify(eth_hdr[0])	# Destination MAC address
	src_mac 	= binascii.hexlify(eth_hdr[1])	# Source MAC address
	proto 		= eth_hdr[2]	# Next protocol
	
	# Clear the screen 
	# os.system("clear")
	
	print "+=============ETHERNET HEADER=============+"
	print "Dest MAC:\t\t%s:%s:%s:%s:%s:%s" % (dest_mac[:2], dest_mac[2:4], dest_mac[4:6], dest_mac[6:8], dest_mac[8:10], dest_mac[10:12])
	print "Source MAC:\t\t%s:%s:%s:%s:%s:%s" % (src_mac[:2], src_mac[2:4], src_mac[4:6], src_mac[6:8], src_mac[8:10], src_mac[10:12])
	
	if hex(proto) == "0x800": 	#IPv4
		ip_bool = True
		print "Protocol:\t\tIP\n"
	else:
		ip_bool = False
		print "Protocol:\t\t**OTHER**\n"
	data = data[14:]
	return data, ip_bool
	

def main():
	
	sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	# sniffer_socket.bind(()) <-- Raw sockets don't bind to anything, just receive
	recv_data = sniffer_socket.recv(2048)
	
	data, ip_bool = analyze_ether_header(recv_data)
	if ip_bool:
		data, next_proto = analyze_IP_header(data)
	else:
		next_proto = 0
	
	if (next_proto == "TCP"):
		data = analyze_TCP_header(data)
	elif (next_proto == "UDP"):
		data = analyze_UDP_header(data)
	elif (next_proto == "ICMP"):
		data = analyze_ICMP_header(data)
	else:
		print "[-] Protocol invalid."
	print "Data:"
	
	print data
	
	hexData = " ".join(x.encode('hex') for x in data)
	# print hexData		# troubleshooting purposes
	
	hexData1 = hexData.split(" ", len(hexData))
	for i in range(len(hexData1)):
		if (i % 8 == 0):
			print "\n"
		
		print hexData1[i],
		
	print "\n\n"
	
	
while(True):
	main()
