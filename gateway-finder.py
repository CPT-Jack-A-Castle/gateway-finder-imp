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
		"blue":'\033[94m',
		"end":'\033[0m',
		"green":'\033[92m',
		"orange":'\033[93m',
		'red':'\033[93m',
		'purple':'\033[95m',
		'bold':'\033[1m',
		'underline':'\033[4m'
	}

	print(bcolors[color] + string_to_print + bcolors['end'])


def load_objects(object_type):
	if object_type == 'mac':
		object_name = 'MAC'
		object_regex = '([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})'

		options_load_file = options.macfile
		options_load_string = options.mac

	elif object_type == 'ip':
		object_name = 'IP'
		object_regex = '(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))'


		options_load_file = options.ipfile
		options_load_string = options.ip
	else:
		sys.exit(0)

	objects = []

	if options_load_file:
		# Load next-hop mac address
		macfh = open(options_load_file, 'r')
		lines = list(map(lambda x: x.rstrip(), macfh.readlines()))
		#ipofmac = {}
		print('[+] Parsing file with %s addresses' % object_name )
		for i in range (len(lines)):
		#for line in lines:
			m = re.search(object_regex,lines[i])
			if not m:
				print('[-] \t%d. There are no %s address in this line: "%s"' % (i,object_name,lines[i]))
			else:
				print('[+] \t%d. Append %s: %s' % (i,object_name,m.group()))
				#print('[+] Append mac: %s'% m)
				objects.append(m.group())

		printc("[+] Using %s %s addresses from %s" % (len(objects),object_name,options_load_file),'blue')

		if len(objects) == 0:
			print("[E] No %s addresses found in %s" % (object_name,options_load_file))
			sys.exit(0)

	elif options_load_string:
		m = re.search(object_regex,options_load_string)
		if not m:
			printc('[E] Not valid %s address: "%s"' % (object_name, options_load_string),'orange')
			sys.exit(0)
		else:
			printc('[+] Using %s: %s' % (object_name,m.group()),'blue')
			objects.append(m.group())

	return(objects)

def create_packets(macs, ips):
	# Build list of packets to send
	seq = 0

	packets = []
	for mac in macs:
		for ip in ips:

			# =========================== ICMP =========================== 
			# Echo request, TTL=1
			packets.append({ 
				'packet': Ether(dst=mac)/IP(dst=ip,ttl=1)/ICMP(seq=seq),
				'type': 'ping', 
				'dstip': ip, 
				'dstmac': mac, 
				'seq': 0, 
				'message': '%s  appears to route ICMP Ping packets to %s.  Received ICMP TTL Exceeded in transit response.' % (mac, ip) 
				})

			# Echo request
			packets.append({
				'packet': Ether(dst=mac)/IP(dst=ip)/ICMP(seq=seq),
				'type': 'ping', 
				'dstip': ip, 
				'dstmac': mac, 
				'seq': 10, 
				'message': '%s - successfully ping host %s (ping %s via %s)' % (mac,ip,ip,mac) 
				})

			# =========================== TCP =========================== 
			# TCP SYN to port 80, TTL=1
			tcp80_ttl1_syn_seq = random.randint(0,65535)
			packets.append({ 
				'packet': Ether(dst=mac)/IP(dst=ip,ttl=1)/TCP(seq=tcp80_ttl1_syn_seq,sport=random.randint(4096,65535),dport=80), 
				'type': 'tcpsyn', 
				'dstip': ip, 
				'dstmac': mac, 
				'seq': tcp80_ttl1_syn_seq, 
				'message': '%s  appears to route TCP packets %s:80.  Received ICMP TTL Exceeded in transit response.' % (mac, ip) 
				})

			# TCP SYN to port 80
			tcp80_syn_seq = 100
			packets.append({ 
				'packet': Ether(dst=mac)/IP(dst=ip)/TCP(seq=tcp80_syn_seq,sport=random.randint(4096,65535),dport=80), 
				'type': 'tcpsyn', 
				'dstip': ip, 
				'dstmac': mac, 
				'seq': tcp80_syn_seq, 
				'message': 'We can reach TCP port 80 on %s via %s ' % (ip, mac) 
				})

			# TCP SYN to port 443
			tcp443_syn_seq = random.randint(0,65535)
			packets.append({ 
				'packet': Ether(dst=mac)/IP(dst=ip)/TCP(seq=tcp443_syn_seq,sport=random.randint(4096,65535),dport=443), 
				'type': 'tcpsyn',
				'dstip': ip,
				'dstmac': mac,
				'seq': tcp443_syn_seq,
				'message': 'We can reach TCP port 443 on %s via %s ' % (ip, mac) })

			# TCP SYN to port 23
			tcp23_syn_seq = random.randint(0,65535)
			packets.append({ 
				'packet': Ether(dst=mac)/IP(dst=ip)/TCP(seq=tcp23_syn_seq,sport=random.randint(4096,65535),dport=23), 
				'type': 'tcpsyn',
				'dstip': ip,
				'dstmac': mac,
				'seq': tcp23_syn_seq,
				'message': 'We can reach TCP port 23 on %s via %s ' % (ip, mac) })

	return(packets)

def processreply(p,packets):
	# This might error if the packet isn't what we're expecting
	try:
		if p[IP].proto == 1: # ICMP
			if p[ICMP].type == 11 and p[ICMP].code == 0:
				if p[IPerror].proto == 1: # response to ICMP packet
					seq = p[ICMP][ICMPerror].seq
					printc("[+] %s" % packets[seq]['message'],'green')
					print("\tReceived reply: %s" % p.summary())
				if p[IPerror].proto == 6: # response to TCP packet
					seq = p[ICMP][TCPerror].seq
					printc("[+] %s" % packets[seq]['message'],'green')
					print("\tReceived reply: %s" % p.summary())
			else:
				seq = p[ICMP].seq
				printc("[+] %s" % packets[seq]['message'],'green')
				print("\tReceived reply: %s" % p.summary())

		elif p[IP].proto == 6: # TCP
			print('!!!')
			if p[IP].src == options.ip and (p[TCP].sport in (80,443,23)):
				print(packets)
				seq = p[TCP].ack - 1 # remote end increments our seq by 1
				print('p[TCP].ack',p[TCP].ack)
				print(packets[101])
				printc("[+] %s" % packets[seq]['message'],'green')
				print("\tReceived reply: %s" % p.summary())
				print(p.info())
	except:
		print("[E] Received unexpected packet.  Ignoring.")
		print('p[IP].proto',p[IP].proto)
	return False

def send_and_sniff(packets, verbosity_level):
	pid = os.fork()
	print('\nPID',pid)
	if pid:
		# parent will send packets
		# give child time to start sniffer
		sleep(2) 
		print("Parent processing sending packets...")
		for packet in packets:
			sendp(packet['packet'], verbose=verbosity_level)
		print("Parent finished sending packets")

		# give child time to capture last reply
		sleep(2) 
		print("Parent killing sniffer process")
		os.kill(pid, signal.SIGTERM)
		print("Parent reaping sniffer process")
		os.wait()
		print("Parent exiting")

		printc("[+] Done",'green')
		sys.exit(0)
		
	else:
		# child will sniff
		filter_part_initail="ip and not arp"
		# icmp[0] = 11 - that code meants icmp type "Time-to-live exceed"
		# icmp[0] = 0 - that code meants icmp type "Reply"
		filter_part_icmp ="icmp[0] = 11 or icmp[0] = 0"
		filter_part_tcp="src host %s" % (options.ip)
		filter_part_tcp_80="tcp and port 80"
		filter_part_tcp_443="tcp and port 443"
		filter_part_tcp_23="tcp and port 23"
		filter_string = "%s and ((%s) or (%s and ( (%s) or (%s) or (%s) ) ))" %(
			filter_part_initail,
			filter_part_icmp,
			filter_part_tcp, 
			filter_part_tcp_80, 
			filter_part_tcp_443,
			filter_part_tcp_23)
		#filter_string="ip and not arp and ((icmp and icmp[0] = 11 and icmp[1] = 0) or (src host %s and (icmp or (tcp and port 80))))" % (options.ip)
		#              'ip and not arp ((icmp and icmp[0] = 11 and icmp[1] = 0) or (src host 87.250.250.242 and (tcp and port 80) or (tcp and port 443) or (tcp and port 23)))
		#filter=""

		print("Child process sniffing on %s with filter:"%options.interface)
		printc("\t%s\n"%filter_string,"orange")

	sniff(iface=options.interface, store = 0, filter=filter_string, prn=None, lfilter=lambda x: processreply(x,packets))

if __name__ == '__main__':

	version = "1.3"
	print("GFI. Gateway-finder-improved. Version %s" % version,'\n')

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
	parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output")
	parser.add_option("-6", "--ipv6", dest="Use ipv6 address", action="store_true", default=False, help="Use ipv6 addresss")
	parser.add_option("-i", "--interface", dest="interface", help="Network interface to use")

	(options, args) = parser.parse_args()

	#print(options.macfile)
	#print(options.mac)
	#print('(options.macfile or options.mac)',(options.macfile or options.mac))

	if not (options.macfile or options.mac):
		printc("[E] No macs.txt specified.  -h for help.",'red')
		sys.exit(0)

	if not (options.ipfile or options.ip):
		printc("[E] No target IP specified.  -h for help.",'red')
		sys.exit(0)

	if not (options.interface ):
		printc("[E] No interface specified.  -h for help.",'red')
		sys.exit(0)

	printc("[+] Using interface: %s"%options.interface,'blue')


	# Verbosity settings
	verbosity_level = 0 
	if options.verbose:	verbosity_level = 1
	printc("[+] Using verbose: %s"%options.verbose,'blue')

	macs = load_objects('mac')
	ips = load_objects('ip')
	packets = create_packets(macs, ips)

	print('packets',packets)
	print("[+] Will be sending %d packets. %d packet[s] for each combinations" % (len(packets), len(packets)/(len(macs)*len(ips))))

	send_and_sniff(packets,verbosity_level)