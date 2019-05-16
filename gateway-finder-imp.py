#!/usr/bin/python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

import os
import sys
import re
from time import sleep
import signal
import argparse
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
	ipv4_regex = '(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))'
	ipv6_regex = '\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*'

	addresses = {
		'dst_macs':[],
		'dst_ips':[]
	}

	if options.ipv6:
		ipmeta_regex = ipv6_regex
		iptype = "IPv6"
	else:
		ipmeta_regex = ipv4_regex
		iptype = "IPv4"

	if options.macfile:

		# Load file with next-hop mac addresses
		mac_file = open(options.macfile, 'r')
		lines = list(map(lambda x: x.rstrip(), mac_file.readlines()))

		print('[I] Parsing file with gateway MAC addresses: %s ' % paint_s(options.macfile,'green') )
		for i in range (len(lines)):

			# If regex is true 
			found_single_mac = re.search(mac_regex,lines[i])
			found_single_ip = re.search(ipmeta_regex,lines[i])

			if found_single_mac: found_single_mac = found_single_mac.group()
			if found_single_ip: found_single_ip = found_single_ip.group()

			# If we have MAC and corresponding IP from a file
			if found_single_mac and found_single_ip:
				print('[+] \t%d. Append destination MAC %s and matched %s %s ' %(i,paint_s(found_single_mac,'green'),iptype,paint_s(found_single_ip,'green')) )
				addresses['dst_macs'].append(
					{'gw_mac':found_single_mac,'gw_ip':found_single_ip}
				)

			# If we have only MAC from a file
			if found_single_mac and not found_single_ip:
				print('[+] \t%d. Append only destination MAC %s from this line ' %(i,paint_s(found_single_mac,'green')))
				addresses['dst_macs'].append(
					{'gw_mac':found_single_mac,'gw_ip':''}
				)

			if not found_single_mac:
				printc('[-] \t%d. This line does not contain valid MAC: "%s"' % (i,paint_s(lines[i],'orange')) )

		if len(addresses['dst_macs'] ) != 0:
			printc("[I] Will be using %d gateway MAC addresses" % len(addresses['dst_macs'] ),'green')
		else:
			princ("[E] There are no valid MAC addresses in a file",'red')
			sys.exit(0)

	if options.mac:
		found_single_mac = re.search(mac_regex, options.mac)

		if found_single_mac:
			found_single_mac = found_single_mac.group()
			print('[+] Using destination MAC: %s' % paint_s(found_single_mac,'green') )
			addresses['dst_macs'].append(
				{'gw_mac':found_single_mac,'gw_ip':''}
			)

		else:
			print(paint_s('[E] Not valid destination MAC: "%s"' % options.mac,'red') )
			sys.exit(0)

	if options.ipfile:

		# Load file with next-hop mac addresses
		mac_file = open(options.ipfile, 'r')
		lines = list(map(lambda x: x.rstrip(), mac_file.readlines()))

		print('[I] Parsing file with destination %s addresses: %s' % (iptype,paint_s(options.ipfile,'blue')) )
		for i in range (len(lines)):

			# If regex is true 
			found_single_ip = re.search(ipmeta_regex,lines[i])

			if found_single_ip: found_single_ip = found_single_ip.group()

			# If we have an IP address from a file
			if found_single_ip:
				print('[+] \t%d. Append destination %s: %s ' %(i,iptype,paint_s(found_single_ip,'blue')) )
				addresses['dst_ips'].append(
					found_single_ip
				)
			else:
				print('[-] \t%d. This line does not contain valid %s: "%s"' % (i,iptype,paint_s(lines[i],'orange')))


		if len(addresses['dst_ips'] ) != 0:
			printc("[I] Will be using %d destination %s addresses " % (len(addresses['dst_ips']),iptype),'blue')
		else:
			printc("[E] There are no valid %s addresses in a file"%iptype,'red')
			sys.exit(0)

	if options.ip:
		found_single_ip = re.search(ipmeta_regex, options.ip)

		if found_single_ip:
			found_single_ip = found_single_ip.group()
			print('[+] Using destination IP: %s' % paint_s(found_single_ip,'blue') )
			addresses['dst_ips'].append(
				found_single_ip
			)

		else:
			print(paint_s('[E] Not valid destination %s: "%s"' % (iptype, options.ip),'red') )
			sys.exit(0)

	return(addresses)

def create_single_packet(args, single_packet_type, seq, ip_dst, gw_mac, gw_ip, ttl, port_dst):


	# =========================== ICMPv4 creation =========================== 
	if single_packet_type == "icmp":

		# ====== Create scapy packet ======
		if not args.ipv6:
			single_packet_scapy = \
				Ether(src=get_if_hwaddr(args.interface),dst=gw_mac)/ \
				IP(dst=ip_dst,ttl=ttl)/ \
				ICMP(seq=seq)
		else:
			single_packet_scapy = \
				Ether(src=get_if_hwaddr(args.interface),dst=gw_mac)/ \
				IPv6(dst=ip_dst)/ \
				ICMPv6EchoRequest()

		# ====== Create specific message ====== 
		if ttl == 1:
			single_packet_message = '%s - (%s) - to %s - %s - appears to route ICMP Ping packets.  Received ICMP TTL Exceeded in transit response' %\
				(
					paint_s(gw_mac,'green'),
					paint_s(gw_ip,'green'),
					paint_s(ip_dst,'blue'),
					paint_s('ICMP TTL1','purple')
				) 
		else:
			single_packet_message = '%s - (%s) - to %s - %s - successfully ping host (ping %s via %s)'% \
				(
					paint_s(gw_mac,'green'),
					paint_s(gw_ip,'green'),
					paint_s(ip_dst,'blue'),
					paint_s('ICMP','purple'),
					ip_dst,
					gw_ip
				) 

	# =========================== TCP for IPv4 creation =========================== 
	if single_packet_type == "tcp":

		# ====== Create scapy packet ======
		if not args.ipv6:
			single_packet_scapy = \
				Ether(src=get_if_hwaddr(args.interface),dst=gw_mac)/ \
				IP(dst=ip_dst,ttl=ttl)/ \
				TCP(seq=seq,sport=random.randint(2048,65535),dport=port_dst)
		else:
			single_packet_scapy = \
				Ether(src=get_if_hwaddr(args.interface),dst=gw_mac)/ \
				IPv6(dst=ip_dst)/ \
				TCP(seq=seq,sport=random.randint(2048,65535),dport=port_dst)


		# ====== Create specific message ====== 
		if ttl == 1:
			single_packet_message = '%s - (%s) - to %s - %s - appears to route TCP packets %s.  Received ICMP TTL Exceeded in transit response.' % \
				(
					paint_s(gw_mac,'green'),
					paint_s(gw_ip,'green'),
					paint_s(ip_dst,'blue'),
					paint_s('TCP %s' % port_dst,'purple'),
					ip_dst
				) 
		else:
			single_packet_message = '%s - (%s) - to %s - %s - we can reach TCP port %s on %s via specified MAC '% \
				(
					paint_s(gw_mac,'green'),
					paint_s(gw_ip,'green'),
					paint_s(ip_dst,'blue'),
					paint_s('TCP %s' % port_dst,'purple'),
					port_dst,
					ip_dst
				) 


	single_packet ={
		'message' : single_packet_message,
		'packet' : single_packet_scapy,
		'type': single_packet_type
	}

	return(single_packet)

def create_packets(args,addresses,checks):
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

			for check in checks:

				if args.verbosemax:
					print(mac_dict,ip)

				# Create uniq seq number
				# it is needed because 
				# filtration of packets when sniffing
				# absolutely depends on a seq number
				# not a brilliant idea - I know
				seq = random.randint(0,65535)
				while seq in packets.keys():
					seq = random.randint(0,65535)

				new_single_packet_check = create_single_packet(
					args=args, 
					single_packet_type=check['type'],
					ttl=check['ttl'],
					seq=seq,
					port_dst=check['port'], 
					ip_dst=ip, 
					gw_mac=mac_dict['gw_mac'], 
					gw_ip=mac_dict['gw_ip']
				)
				packets[seq] = new_single_packet_check

	return(packets)

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
		print("[I] Gateway MAC addr  - Gateway IP addr - Destination IP addr - Test - Comment")
		
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
		#filter_part_tcp="src host %s" % (args.ip)
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
			print("Child process sniffing on %s with filter:" % args.interface)
			printc("\t%s" % filter_string,"orange")

	sniff(iface=args.interface, store = 0, filter=filter_string, prn=None, lfilter=lambda x: processreply(x, packets, verbosity_level))

def info_about_verbosity(args):

	# Verbosity settings

	verbosity_names = {
		0:'None',
		1:'Medium',
		2:'Max'
	}

	verbosity_level = 0
	if args.verbose:	verbosity_level = 1
	elif args.verbosemax: verbosity_level = 2
	print("[+] Using verbose level: %s" % paint_s(verbosity_names[verbosity_level],'purple'))

	return(verbosity_level)

def info_about_ip_version(args):

	if args.ipv6:
		use_ip_version = "IPv6"
		printc("[+] Script cannot sniff IPv6 at the moment, you have to do it manually ",'red')
	else:
		use_ip_version = "IPv4"


	print("[+] Using network protocol: %s version" % paint_s(use_ip_version,'purple'))

def info_check_options(args):

	if not (args.macfile or args.mac):
		printc("[E] No macs.txt specified.  -h for help.",'red')
		sys.exit(0)

	if not (args.ipfile or args.ip):
		printc("[E] No target IP specified.  -h for help.",'red')
		sys.exit(0)

	if not (args.interface ):
		printc("[E] No interface specified.  -h for help.",'red')
		sys.exit(0)

	print("[+] Using interface: %s" % paint_s(args.interface,'purple'))

def load_checks(args):

	checks_base = [
		{'type':'icmp','ttl':1,'port':0},
		{'type':'icmp','ttl':255,'port':0},
		{'type':'tcp','ttl':1,'port':80}
	]
	checks_default = [
		{'type':'icmp','ttl':1,'port':0},
		{'type':'icmp','ttl':255,'port':0},
		{'type':'tcp','ttl':1,'port':80},
		{'type':'tcp','ttl':255,'port':80},
		{'type':'tcp','ttl':255,'port':443}
	]

	if args.ports :
		checks = checks_base
		for port_dst in args.ports:
			single_check = {'type':'tcp','ttl':255,'port':port_dst}
			checks.append(single_check)
	else:
		checks = checks_default

	num_of_checks = len(checks)
	print(paint_s("[I] Will be using %d checks:"%num_of_checks,'purple'))
	for i in range(num_of_checks):
		if checks[i]['type'] == 'tcp':
			print("\t%d. TCP  | TTL: %d | port.dst: %d "%(i,checks[i]['ttl'],checks[i]['port']))
		elif checks[i]['type'] == 'icmp':
			print("\t%d. ICMP | TTL: %d " % (i,checks[i]['ttl']) )

	return(checks)


if __name__ == '__main__':

	version = "1.8"
	printc("\nGFI. Gateway Finder Improved. Version %s\n" % version,'bold')

	parser = argparse.ArgumentParser(usage=\
"Usage: prog -d <ip_address> -m <mac_addr_of_next_hop> -i <interface>\n\n\
Ex1:  ./gateway-finder-imp.py -d 8.8.8.8 -m de:ad:be:af:de:ad -i wlp3s0 \n\
Ex2:  ./gateway-finder-imp.py -D file_with_dst_IPs.txt -m de:ad:be:af:de:ad -i eth0 \n\
Ex3:  ./gateway-finder-imp.py -D file_with_dst_IPs.txt -M file_with_nex_hop_MACs.txt -i ppp0 \n\
Ex4:  ./gateway-finder-imp.py -D file_with_dst_IPs.txt -M file_with_nex_hop_MACs.txt -i eth1 -p 22 443 80 8080 23\n\
Ex5:  ./gateway-finder-imp.py -d 2a00:1450:4010:c05::64 -M mac_with_ipv6_0.txt -i wlp3s0 -p 443 80 -6 --v\n\n\
Tries to find a layer-3 gateway to the Internet.  Attempts to reach an IP\n\
address using: ICMP ping and TCP SYN to port 80/443/23 via each potential gateway\n" )

	group_args_ip = parser.add_mutually_exclusive_group()
	group_args_ip.add_argument("-d", dest="ip", help="Internet IP to probe")
	group_args_ip.add_argument("-D", dest="ipfile", help="File containing IP addresses to probe")

	group_args_mac = parser.add_mutually_exclusive_group()
	group_args_mac.add_argument("-m", dest="mac", help="Next hop MAC addresses")
	group_args_mac.add_argument("-M", dest="macfile", help="File containing MAC addresses")

	group_args_verbose = parser.add_mutually_exclusive_group()
	group_args_verbose.add_argument("--v", dest="verbose", action="store_true", default=False, help="Verbose output")
	group_args_verbose.add_argument("--vv", dest="verbosemax", action="store_true", default=False, help="More verbose output")

	parser.add_argument("-6", dest="ipv6", action="store_true", default=False, help="Use ipv6 addresss")
	parser.add_argument("-i", dest="interface", help="Network interface to use")
	parser.add_argument("-p", dest="ports",type=int,default=[],nargs='+',help="ports that will be used tor TCP SYN ttl 255 test")

	args = parser.parse_args()

	info_check_options(args)

	verbosity_level = info_about_verbosity(args)
	info_about_ip_version(args)

	addresses = load_objects_new(args)

	# Check - it is one single
	# test for a gateway
	checks = load_checks(args)

	packets = create_packets(args=args,addresses=addresses,checks=checks)

	# for debug
	if args.verbosemax:
		print('addresses\n',addresses,'\n')
		for p in packets.keys():
			print(p,packets[p])
	#print('packets',packets)

	num_of_packets_created = len(packets)
	num_of_packets_per_combo = len(addresses['dst_macs'])*len(addresses['dst_ips'])

	printc("[I] Will be sending %s packets: %s packet[s] for an each check" % 
		(
			num_of_packets_created,
			num_of_packets_per_combo
		),'purple'
	)

	send_and_sniff(packets, addresses['dst_ips'], verbosity_level)