This is a slightly improved version of an original [gateway-finder](https://github.com/pentestmonkey/gateway-finder) with python3 and support of IPv6

The homepage of original project is: [http://pentestmonkey.net/tools/gateway-finder](http://pentestmonkey.net/tools/gateway-finder)

----
**Current version: 1.6**

----

## Info

![gw-finder-img](https://github.com/whitel1st/gateway-finder/blob/master/gw-finder.png)

Gateway-finder is a scapy script that will help you determine which of the systems on the local LAN has IP forwarding enabled and which can reach the Internet.

This can be useful during Internal pentests when you want to quickly check for unauthorised routes to the Internet (e.g. rogue wireless access points) or routes to other Internal LANs.  It doesn't perform a hugely thorough check, but it is quick at least.  It's python, so it should be easy to modify to fit your needs.

You give the script the IP address of a system on the Internet you're trying to reach and it will send the following probes via each system on the local LAN:

* An ICMP Ping
* An ICMP Ping with a TTL of 1
* A TCP SYN packet to port 80 with a TTL of 1
* A TCP SYN packet to port 443
* A TCP SYN packet to port 23

It will report separately which systems send an ICMP "TTL exceeded in transit" message back (indicating that they're routers) and which respond to the probe (indicating that they're gateways to the Internet).


## Install 

`pip install -r requirements.txt`

## Run

- `gateway-finder-imp.py`
	- `-h` - help
	- `-M <MAC>` - use file with next-hop MACs 
	- `-m <file_with_MACs>` - use selected next-hop MAC 
	- `-d <IP>` - use selected destination IPs
	- `-D <file_with_IPs>` - use file with selected destination IPs
	- `-i <interface_name>` - use selected network interface
- examples
	- `gateway-finder.py -d 8.8.8.8 -m de:ad:be:af:de:ad  -i enp0s31f6` 
	use selected next-hop MAC and selected destination IP
	- `gateway-finder.py -D dst_hosts.txt -M next_hop_macs.txt  -i wlp3s0` -  use selected next-hop MAC and file with selected destination IPs
	- `gateway-finder.py -d  8.8.8.8 -M next_hop_macs.txt  -i eth0` - use file with next-hop MACs and file with selected destination IPs

Tries to find a layer-3 gateway to the Internet.  Attempts to reach an IP
address using ICMP ping and TCP SYN to port 80 via each potential gateway

### How to identify systems on the local LAN 

Use your favourite ARP scanning to identify systems on the local LAN. Save the output (I use to arp.txt in the example below).


- For IPv4
	- `arp-scan`
		- `arp-scan -l`
		```bash
		arp-scan -l | tee arp_scan_macs.txt


		Interface: eth0, datalink type: EN10MB (Ethernet)
		Starting arp-scan 1.6 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
		10.0.0.100     00:13:72:09:ad:76       Dell Inc.
		10.0.0.200     00:90:27:43:c0:57       INTEL CORPORATION
		10.0.0.254     00:08:74:c0:40:ce       Dell Computer Corp.

		3 packets received by filter, 0 packets dropped by kernel
		Ending arp-scan 1.6: 256 hosts scanned in 2.099 seconds (121.96 hosts/sec).  3 responded
		```
	- `arp`
		- `arp -a`
		```bash
		arp -a | tee arp_macs.txt

		(10.10.2.1) at 1f:2e:39:d7:2f:04 [ether] on eth0
		(10.10.2.3) at 1f:23:39:d8:2e:44 [ether] on eth0
		```
		- `arp` - filter only macs
		```bash
		arp -a | arp -a | cut -d ' ' -f 4 | tee arp_macs.txt

		1f:2e:39:d7:2f:04
		1f:23:39:d8:2e:44
		```

- For IPv6
	- `ping6`
		- `ping6 ff02::1`
		- `ping6 ff02::2`
		- `ping6 ff02::5`
	- `nmap`
		- `sudo nmap -6 -vv --script targets-ipv6-multicast-slaac.nse`


### ToDo

- [x] rewritten to python3 using modular approach 
- [x] use file with IP addresses
- [x] nice color print
- [x] fix regex mistakes 
- [x] fix capture filter
- [x] rewrite program to make it more readable and easy to custom
- [x] change verbosity
- [ ] IPv6 support
- [ ] develop a convenient way to add new network tests 
