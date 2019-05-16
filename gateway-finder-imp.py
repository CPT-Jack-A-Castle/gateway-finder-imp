#!/usr/bin/python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#from scapy.all import Ether,IP,ICMP,TCP,sendp,sniff
import os
import sys
import re
from time import sleep
import signal
from optparse import OptionParser
import random

def printc(string_to_print,color):

	bcolors = {
		"end":'\033[0m',
		"green":'\033[92m',
		"orange":'\033[93m',
		"blue":'\033[94m',
		'purple':'\033[95m',
		'red':'\033[91m',
		'bold':'\033[1m',
		'underline':'\033[4m'
	}

	print(bcolors[color] + string_to_print + bcolors['end'])

def paint_s(to_paint,color):

	bcolors = {
		"end":'\033[0m',
		"green":'\033[92m',
		"orange":'\033[93m',
		"blue":'\033[94m',
		'purple':'\033[95m',
		'red':'\033[91m',
		'bold':'\033[1m',
		'underline':'\033[4m'
	}
	return(bcolors[color] + str(to_paint) + bcolors['end'])


def load_objects_new(options):


	mac_regex = '([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})'
	ip_regex = '(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))'

	addresses = {
		'dst_macs':[],
		'dst_ips':[]
	}


	if options.macfile:

		# Load file with next-hop mac addresses
		mac_file = open(options.macfile, 'r')
		lines = list(map(lambda x: x.rstrip(), mac_file.readlines()))

		print('[I] Parsing file with gateway MAC addresses: %s ' % paint_s(options.macfile,'green') )
		for i in range (len(lines)):

			# If regex is true 
			found_single_mac = re.search(mac_regex,lines[i])
			found_single_ip = re.search(ip_regex,lines[i])

			if found_single_mac: found_single_mac = found_single_mac.group()
			if found_single_ip: found_single_ip = found_single_ip.group()

			# If we have MAC and corresponding IP from a file
			if found_single_mac and found_single_ip:
				print('[+] \t%d. Append destination MAC %s and matched IP %s ' %(i,paint_s(found_single_mac,'green'),paint_s(found_single_ip,'green')) )
				addresses['dst_macs'].append(
					{'mac':found_single_mac,'ip_gw':found_single_ip}
				)

			# If we have only MAC from a file
			if found_single_mac and not found_single_ip:
				print('[+] \t%d. Append only destination MAC %s from this line ' %(i,paint_s(found_single_mac,'green')))
				addresses['dst_macs'].append(
					{'mac':found_single_mac,'ip_gw':''}
				)

			if not found_single_mac:
				printc('[-] \t%d. This line does not contain valid MAC: "%s"' % (i,paint_s(lines[i],'orange')) )

	if options.mac:
		found_single_mac = re.search(mac_regex, options.mac)

		if found_single_mac:
			found_single_mac = found_single_mac.group()
			print('[+] Using destination MAC: %s' % paint_s(found_single_mac,'green') )
			addresses['dst_macs'].append(
				{'mac':found_single_mac,'ip_gw':''}
			)

		else:
			print(paint_s('[E] Not valid destination MAC: "%s"' % options.mac,'red') )
			sys.exit(0)

	if options.ipfile:

		# Load file with next-hop mac addresses
		mac_file = open(options.ipfile, 'r')
		lines = list(map(lambda x: x.rstrip(), mac_file.readlines()))

		print('[I] Parsing file with destination IP addresses: %s' % paint_s(options.ipfile,'blue') )
		for i in range (len(lines)):

			# If regex is true 
			found_single_ip = re.search(ip_regex,lines[i])

			if found_single_ip: found_single_ip = found_single_ip.group()

			# If we have an IP address from a file
			if found_single_ip:
				print('[+] \t%d. Append destination IP: %s ' %(i,paint_s(found_single_ip,'blue')) )
				addresses['dst_ips'].append(
					found_single_ip
				)
			else:
				print('[-] \t%d. This line does not contain valid IP: "%s"' % (i,paint_s(lines[i],'orange'))) 


	if options.ip:
		found_single_ip = re.search(ip_regex, options.ip)

		if found_single_ip:
			found_single_ip = found_single_ip.group()
			print('[+] Using destination IP: %s' % paint_s(found_single_ip,'blue') )
			addresses['dst_ips'].append(
				found_single_ip
			)

		else:
			print(paint_s('[E] Not valid destination IP: "%s"' % options.ip,'red') )
			sys.exit(0)

	return(addresses)


def create_packets(macs):
	# Build list of packets to send
	seq = 0

	# packets = 
	# {
	# 	seq = {
	# 		packet: Ether/IP/ICMP,
	# 		dstip: 0.0.0.0,
	# 		message : "smt"
	# 	},

	packets = {	}

	for mac_dict in addresses['dst_macs']:

		for ip in addresses['dst_ips']:


			# =========================== ICMP creation =========================== 
			# Echo request, TTL=1
			icmp_ttl1_seq = random.randint(0,65535)
			packets[icmp_ttl1_seq]={ 
				'packet': Ether(src=get_if_hwaddr(options.interface),dst=mac_dict['mac'])/IP(dst=ip,ttl=1)/ICMP(seq=icmp_ttl1_seq),
				'type': 'ping', 
				'message': '%s - (%s) - to %s - ICMP TTL1 - appears to route ICMP Ping packets.  Received ICMP TTL Exceeded in transit response' % 
					(
						paint_s(mac_dict['mac'],'green'),
						paint_s(mac_dict['ip_gw'],'green'),
						paint_s(ip,'blue')
					) 
				}

			# Echo request
			icmp_seq = random.randint(0,65535)
			packets[icmp_seq]={ 
				'packet': Ether(src=get_if_hwaddr(options.interface),dst=mac_dict['mac'])/IP(dst=ip)/ICMP(seq=icmp_seq),
				'type': 'ping', 
				'message': '%s - (%s) - to %s - ICMP - successfully ping host (ping %s via %s)'% 
					(
						paint_s(mac_dict['mac'],'green'),
						paint_s(mac_dict['ip_gw'],'green'),
						paint_s(ip,'blue'),
						ip,
						mac_dict['ip_gw']
					) 
				}

			# # =========================== TCP creation =========================== 
			# # TCP SYN to port 80, TTL=1
			# tcp80_ttl1_syn_seq = random.randint(0,65535)
			# packets[tcp80_ttl1_syn_seq]={ 
			# 	'packet': Ether(src=get_if_hwaddr(options.interface),dst=mac)/IP(dst=ip,ttl=1)/TCP(seq=tcp80_ttl1_syn_seq,sport=random.randint(4096,65535),dport=80), 
			# 	'type': 'tcpsyn', 
			# 	'dstip': ip, 
			# 	'dstmac': mac, 
			# 	'message': '%s - TCP test 80 - ttl 1- appears to route TCP packets %s:80.  Received ICMP TTL Exceeded in transit response.' % (mac, ip) 
			# 	}

			# # TCP SYN to port 80
			# tcp80_syn_seq = random.randint(0,65535)
			# packets[tcp80_syn_seq]={
			# 	'packet': Ether(src=get_if_hwaddr(options.interface),dst=mac)/IP(dst=ip)/TCP(seq=tcp80_syn_seq,sport=random.randint(4096,65535),dport=80), 
			# 	'type': 'tcpsyn', 
			# 	'dstip': ip, 
			# 	'dstmac': mac, 
			# 	'message': '%s - TCP test 80 - we can reach TCP port 80 on %s via specified MAC ' % (mac, ip) 
			# 	}

			# # TCP SYN to port 443
			# tcp443_syn_seq = random.randint(0,65535)
			# packets[tcp443_syn_seq]={
			# 	'packet': Ether(src=get_if_hwaddr(options.interface),dst=mac)/IP(dst=ip)/TCP(seq=tcp443_syn_seq,sport=random.randint(4096,65535),dport=443), 
			# 	'type': 'tcpsyn',
			# 	'dstip': ip,
			# 	'dstmac': mac,
			# 	'message': '%s - TCP test 443 - we can reach TCP port 443 on %s via specified MAC ' % (mac, ip) 
			# 	}

			# # TCP SYN to port 23
			# tcp23_syn_seq = random.randint(0,65535)
			# packets[tcp23_syn_seq]={ 
			# 	'packet': Ether(src=get_if_hwaddr(options.interface),dst=mac)/IP(dst=ip)/TCP(seq=tcp23_syn_seq,sport=random.randint(4096,65535),dport=23), 
			# 	'type': 'tcpsyn',
			# 	'dstip': ip,
			# 	'dstmac': mac,
			# 	'message': '%s - TCP test 23- we can reach TCP port 23 on %s via specified MAC ' % (mac, ip) 
			# 	}

	return(packets)

def expand(x):
	yield x.name
	while x.payload:
		x = x.payload
		yield x.name

def processreply(p, packets, verbosity_level):
	# This might error if the packet isn't what we're expecting
	try:
		# ========== ICMP processing ==========
		if p[IP].proto == 1:  
			if p[ICMP].type == 0: # reply to ICMP packet
				seq = p[ICMP].seq

			elif p[ICMP].type == 11 and p[ICMP].code == 0:
				if p[IPerror].proto == 1: # response to ICMP with TTL=1
					seq = p[ICMP][ICMPerror].seq
				elif p[IPerror].proto == 6: # response to TCP with TTL=1
					seq = p[IPerror].seq	

		# ========== TCP processing ==========
		elif p[IP].proto == 6: 
			if (p[TCP].sport in (80,443,23)):
				seq = p[TCP].ack - 1 # remote end increments our seq by 1

		printc("[+] %s" % packets[seq]['message'],'green')
		
		if verbosity_level:
			print("\tReceived reply: %s" % p.summary())
	except:
		if verbosity_level:
			print("[E] Received unexpected packet (IP type = %s). Ignoring."%p[IP].proto)
	return False

def send_and_sniff(packets, ip_addresses_dst, verbosity_level):
	pid = os.fork()

	if verbosity_level: print('\nPID',pid)

	if pid:
		# parent will send packets
		# give child time to start sniffer
		sleep(2) 
		printc("\n[I] Parent processing sending packets...",'purple')
		print("[ ] Gateway MAC addr  - Gateway IP addr - Destination IP addr - Test - Comment")
		
		for some_packet_seq in packets:
			sendp(packets[some_packet_seq]['packet'], verbose=0)
		printc("[I] Parent finished sending packets\n",'purple')

		# give child time to capture last reply
		sleep(2) 
		printc("[I] Parent killing sniffer process",'purple')
		os.kill(pid, signal.SIGTERM)
		printc("[I] Parent reaping sniffer process",'purple')
		os.wait()
		printc("[I] Parent exiting",'purple')

		printc("[+] Done",'green')
		sys.exit(0)
		
	else:
		# child will sniff
		filter_part_initail="ip and not arp"
		# icmp[0] = 11 - that code meants icmp type "Time-to-live exceed"
		# icmp[0] = 0 - that code meants icmp type "Reply"
		filter_part_icmp ="icmp[0] = 11 or icmp[0] = 0"
		#filter_part_tcp="src host %s" % (options.ip)
		filter_part_tcp=""
		for i in range(len(ip_addresses_dst)-1):
			filter_part_tcp += "(src host %s) or " % ip_addresses_dst[i]
		filter_part_tcp += "(src host %s)" % ip_addresses_dst[len(ip_addresses_dst)-1]

		filter_part_tcp_80="tcp and port 80"
		filter_part_tcp_443="tcp and port 443"
		filter_part_tcp_23="tcp and port 23"
		filter_string = "(%s) and ((%s) or ( (%s) and ( (%s) or (%s) or (%s) ) ))" %(
			filter_part_initail,
			filter_part_icmp,
			filter_part_tcp, 
			filter_part_tcp_80, 
			filter_part_tcp_443,
			filter_part_tcp_23)

		if verbosity_level:
			print("Child process sniffing on %s with filter:" % options.interface)
			printc("\t%s" % filter_string,"orange")

	sniff(iface=options.interface, store = 0, filter=filter_string, prn=None, lfilter=lambda x: processreply(x, packets, verbosity_level))

if __name__ == '__main__':

	version = "1.6"
	printc("\nGFI. Gateway Finder Improved. Version %s\n" % version,'bold')

	parser = OptionParser(usage=\
"Usage: %prog -d <ip_address> -m <mac_addr_of_next_hop> -i <interface>\n\n\
Ex1:\t%prog -d 8.8.8.8 -m de:ad:be:af:de:ad	-i wlp3s0 \n\
Ex2:\t%prog -D file_with_dst_IPs.txt -m de:ad:be:af:de:ad -i eth0 \n\
Ex3:\t%prog -D file_with_dst_IPs.txt -M file_with_nex_hop_MACs.txt -i ppp0 \n\n\
Tries to find a layer-3 gateway to the Internet.  Attempts to reach an IP\n\
address using ICMP ping and TCP SYN to port 80 via each potential gateway\n\
in macs.txt (ARP scan to find MACs)")
	parser.add_option("-d", "--ip", dest="ip", help="Internet IP to probe")
	parser.add_option("-D", "--ipfile", dest="ipfile", help="File containing IP addresses to probe")
	parser.add_option("-m", "--mac", dest="mac", help="Next hop MAC addresses")
	parser.add_option("-M", "--macfile", dest="macfile", help="File containing MAC addresses")
	parser.add_option("--v", dest="verbose", action="store_true", default=False, help="Verbose output")
	parser.add_option("--vv", dest="verbosemax", action="store_true", default=False, help="More verbose output")
	parser.add_option("-6", "--ipv6", dest="Use ipv6 address", action="store_true", default=False, help="Use ipv6 addresss")
	parser.add_option("-i", "--interface", dest="interface", help="Network interface to use")

	(options, args) = parser.parse_args()

	if not (options.macfile or options.mac):
		printc("[E] No macs.txt specified.  -h for help.",'red')
		sys.exit(0)

	if not (options.ipfile or options.ip):
		printc("[E] No target IP specified.  -h for help.",'red')
		sys.exit(0)

	if not (options.interface ):
		printc("[E] No interface specified.  -h for help.",'red')
		sys.exit(0)


	print("[+] Using interface: %s" % paint_s(options.interface,'purple'))


	verbosity_names = {
		0:'None',
		1:'Medium'
	}
	# Verbosity settings
	verbosity_level = 0
	if options.verbose:	verbosity_level = 1
	elif options.verbosemax: verbosity_level = 2
	print("[+] Using verbose level: %s" % paint_s(verbosity_names[verbosity_level],'purple'))

	addresses = load_objects_new(options)

	packets = create_packets(addresses)

	# for debug
	#print('packets',packets)

	num_of_packets_created = len(packets)
	num_of_packets_per_combo = len(addresses['dst_macs'])*len(addresses['dst_ips']) 
	num_of_checks = 2

	print("[I] Total number of MAC gateways: %d " % len(addresses['dst_macs'] ))
	print("[I] Total number of IP destinations: %d " % len(addresses['dst_ips']))
	print("[I] Will be sending %s packets: %s packet[s] for each of %s check[s]" % 
		(
			paint_s(num_of_packets_created,'purple'),
			paint_s(num_of_packets_per_combo,'purple'),
			paint_s(num_of_checks,'purple')
		)
	)

	send_and_sniff(packets, addresses['dst_ips'], verbosity_level)