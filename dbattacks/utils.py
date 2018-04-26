from __future__ import print_function
# Utilities platform for NoSQL Exploitaiton Framework
from ghost import Ghost
from termcolor import colored
import time
import os
from shodan import WebAPI
#import ping
import threading
import warnings
warnings.filterwarnings("ignore")
import socket
import couchdb
from pymongo import MongoClient
import redis
import sys
import queue


def host_up(target):  # Checks Whether the Host is Up or Not

    hostname = target  # example
    response = os.system("ping -c 1 " + hostname+" > /dev/null 2>&1")

    # and then check the response...
    if response == 0:
        print(colored("[+] "+hostname+' is up!', 'green'))
        return True
    else:
        print(colored("\n[-]"+target +
                      ' is down! or Invalid Host Address\n', 'red'))

    """
	try:
		response = ping.quiet_ping(target,count=2)[0]
		if response == 0:
			return True
		else:
			print colored("\n[-]"+target+' is down! or Invalid Host Address\n','red')
			print "[-] Exiting.. "
			#sys.exit()
	except socket.error:
		print colored("[-] Network is unreachable ",'red')
	"""


def scan_target(target):
    mong = False
    cou = False
    red = False

    print(
        colored("\n[!] Scanning Module For NoSQL Framework Launched..... \n", 'blue'))

    try:
        conn = MongoClient(target, 27017)
        popen = "[-] MongoDB port open on " + target + ":27017!\n"
        print(colored(popen, 'green'))
        mong = True
    except:
        print(colored("[-] MongoDB port closed. \n", 'red'))

    try:
        couch = couchdb.Server('http://%s:5984/' % (target))
        check = couch.version()  # Makes sure that the Connection is really established
        popen = "[-] CouchDB port open on " + target + ":5984!\n"
        print(colored(popen, 'green'))
        cou = True
    except socket.error:
        print(colored("[-] CouchDB port closed. \n", 'red'))

    try:
        r_server = redis.Redis(target)
        check = r_server.keys()  # Makes sure that the Connection is really established
        popen = "[-] RedisDB port open on " + target + ":6479! \n"
        print(colored(popen, 'green'))
    #red = True
    except redis.exceptions.ConnectionError:
        print(colored("[-] RedisDB Port Closed \n", 'red'))
    except redis.exceptions.ResponseError:
        popen = "[-] RedisDB port open on " + target + ":6479! \n"
        print(colored(popen, 'green'))

    """try:
		h_base = Connection(host=target, port=8080)
		print colored("[-] H-Base DB port open on " + target + ":8080! \n","green")
	except:
		print colored("[-] H-Base DB port closed ",'red')
	"""

    if red == False and cou == False and mong == False:
        print(colored("No DB Ports Open ", 'red'))


def screenshot(url, creds=False):
    """
    Grab Screenshot of Web Interface

    """
    try:
        ghost = Ghost(wait_timeout=4)
        if creds:
            ghost.open(url, auth=(creds.split(':')[0], creds.split(':')[1]))
            ghost.capture_to(str(time.time())+'.png')
            os.system('mv *.png ./screenshots')
            print(colored(
                "\n[+] Screenshot Succesfull Catpured and Saved @ %s/screen.png" % (os.getcwd()), 'green'))
        else:
            ghost.open(url)
            ghost.capture_to('screen'+str(time.time())+'.png')
            os.system('mv *.png ./screenshots')
            print(colored(
                "\n[+] Screenshot Succesfull Catpured and Saved @ %s/screen.png" % (os.getcwd()), 'green'))
    except Exception as e:
        print(colored("\n[-] Screenshot failed Error : "+str(e), 'red'))


def mass_scan(db_type, file_name):
    #print select
    n = []
    #conn = pymongo.Connection('mongodb://'+target,safe=True)
# File format is IP lists in order
    if db_type == 'mongo':
        files = open(file_name, 'r')
        lines = files.readlines()
        for i in lines:
            n.append(i.strip('\n'))
            # mongo_conn(i.strip('\n'),27017)
        iplist(n)
    if db_type == 'couch':
        files = open(file_name, 'r')
        lines = files.readlines()
        for i in lines:
            couch_conn(i.strip('\n'))
    if db_type == 'redis':
        files = open(file_name, 'r')
        lines = files.readlines()
        for i in lines:
            n.append(i.strip('\n'))
        iplist(n)


class IPGrab(threading.Thread):
    """Threaded Url Grab"""

    def __init__(self, queue, serverobj, type):
        threading.Thread.__init__(self)
        self.queue = queue
        self.serverobj = serverobj
        self.type = type

    def run(self, serverobj, type):
        #conn = pymongo.Connection('mongodb://'+target,safe=True)
        while True:
            url = self.queue.get()
            if select == 'redis':
                redis_conn(url)
            elif select == 'mongo':
                mongo_conn(url, 27017)
            elif select == "couch":
                couch_conn(url)
            elif self.type == 'filecheck':
                get_file_enum(self.serverobj, url)
            # Scan targets here
            # signals to queue job is done
            self.queue.task_done()


def iplist(server_addr, serverobj, type):
    querange = len(server_addr)
    queue_obj = queue.Queue()
    # spawn a pool of threads, and pass them queue instance
    for i in xrange(int(querange)):
        t = IPGrab(queue_obj, serverobj, type)
        t.setDaemon(True)
        t.start()
    # populate queue with data
    for target in server_addr:

        queue_obj.put(target, serverobj, type)
    # wait on the queue until everything has been processed
    queue_obj.join()


def shodan_frame(port):
    """
    Fetches Shodan results by using query of type - 'port:portnumber'

    """
    print(colored(
        "\n[!] Shodan Search Module For NoSQL Framework Launched.....", 'yellow'))
    api = shodan.Shodan("")  # Supply API Key From shodan.io
    if port == 5984:
        query = '{"couchdb":"Welcome","version":""}'
    else:
        query = 'port:%s' % (port)
    result = api.search(query)
    print(
        colored("[!] Would Like to write the Results to a File (y/n) ", 'yellow'))
    choice = raw_input()
    if choice.lower() == 'y':
        file = open('shodan-%s.txt' % (port), 'w')
        for host in result['matches']:
            file.write(host['ip']+"\n")
        print(colored('[+] File to %s/shodan-%s.txt' %
                      (os.getcwd(), port), 'green'))
        file.close()
    else:
        print(colored("[+] Printing Found IP \n", 'blue'))
        for host in result['matches']:
            print(colored("[+] "+host['ip'], 'green'))
