#!/usr/bin/python
# Core Configuration File For Commands and Options

from __future__ import print_function
import sys
import logging

#from sniff import sniffredis
#from sniff import sniffmongo
#from sniff import sniffcouch


from termcolor import colored

from dbattacks import mongoattacks
from dbattacks import couchattacks
from dbattacks import redisattacks
from dbattacks import hbaseattacks
from dbattacks import cassattacks
from dbattacks import utils

#import webattacks
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("ctype.runtime").setLevel(logging.ERROR)


def Config(args):

    mas = False
    paramcheck = []
    specify_params = []
    available = ['mongo', 'couch', 'redis']
    post_status = False
    target = args['ip']
    port = args['port']
    url = args['webapp']
    seldb = args['enum']
    filename = args['file']

    try:

        # Checks whether Host is up
        if args['ip']:
            utils.host_up(target)

        # Credentials
        screen = args['screen'] if args['screen'] else False
        creds = args['auth'] if args['auth'] else False
        authall = args['authall'] if args['authall'] else False
        mass = args['mass'] if args['mass'] else False
        db = args['db'] if args['db'] else 'admin'
        column_select = args['c'] if args['c'] else False
        dump = True if args['dump'] else False
        post_status = True if args['post'] else False
        limit = int(args['limit']) if args['limit'] else 0
        write = args['write'] if args['write'] else False

        # Scan for General DB Targets
        if args['scan']:
            utils.scan_target(target)

        # Web Attacks
        # This is argument is not working correctly - Need to fix - th3r3p0
        # if args['url']:
        #	seldb=args['webapp'] if args['webapp'] else False
        #	if seldb == 'mongo':
        #		filename=['payload/js_inject.txt','payload/js_time']

        # Dictionary Attacks

        if args['dict']:
            seldb = args['dict']
            if args['file']:
                if seldb == 'mongo':
                    if args['port'] or args['db']:
                        pass
                    else:
                        port = 27017
                        db = 'admin'
                    # mongoattacks.mongo_web_interface(target,port,creds,screen)
                    mongoattacks.dict_mongo(filename, target, port, db)
                elif seldb == 'couch':
                    if args['port']:
                        pass
                    else:
                        port = 5984
                    couchattacks.dict_couch(filename, target, port)
                elif seldb == 'redis':
                    if args['port']:
                        pass
                    else:
                        port = 6379
                    redisattacks.dict_redis(filename, target, port)
            else:
                print(colored("[-] Specify File Name", 'red'))

        # Enumeration Check
        if args['enum']:
            seldb = args['enum']
            if seldb == 'mongo':
                if port:
                    pass
                else:
                    port = 27017
                # mongo_web_scan(target)
                try:
                    conn = mongoattacks.mongo_conn(target, port, mass)
                    mongoattacks.mongo_enum(
                        conn, creds, authall, db, column_select, dump, limit, write)
                except Exception as e:
                    print(colored(e, 'red'))
            elif seldb == 'couch':
                if port:
                    pass
                else:
                    port = 5984
                try:
                    # print post_status
                    if db == 'admin':
                        db = ""
                    couch = couchattacks.couch_conn(target, port)
                    couchattacks.couch_enum(
                        couch, target, port, creds, db, column_select, post_status)
                except Exception:
                    print(Exception)
                    print(colored("[-] Enumeration Failed \n", 'red'))
            elif seldb == 'redis':
                if port:
                    pass
                else:
                    port = 6379
                try:
                    r_server = redisattacks.redis_conn(target, port)
                    redisattacks.redis_enum(r_server, creds)
                except Exception:
                    print(colored(e, 'red'))
            elif seldb == 'cassandra':
                if port:
                    pass
                else:
                    port = 9160
                    creds = False
                if db == 'admin':
                    db = False
                cassattacks.cassa_enum(target, port, db, dump)
            elif seldb == 'hbase':
                if port:
                    pass
                else:
                    port = 8080
                hbaseattacks.hbase_enum(port)
            else:
                print(colored("[-] No Support for the Specified DB", 'red'))

        # Mass Scan Settings

        if args['mass'] in available:
            select = args['mass']
            if args['file']:
                mas = True
                mass_scan(args['mass'], args['file'])
            else:
                print(colored("[-] Plse specify File name \n", 'red'))

        # Database Select (Currently available for Mongo,Couch)
        if args['db']:
            db_select = args['db']
            column_select = args['c']
        else:
            db_select = ""
            if args['post'] == 'enable':
                post_status = True

        if args['param']:
            paramcheck = args['param']
            specify_params = paramcheck.split(',')
        else:
            pass

        specify_params = args['param']

        # Scans for WebAPP Attacks
        if args['webapp']:
            webattacks.nosqlweb.attack(url)

        # Redis DOS (2.6+)
        if args['exhaust']:
            if port:
                pass
            else:
                port = 6379
            redisattacks.redis_exhaust(target, port)

        # Redis RCE Check
        if args['remotecheck']:
            if port:
                pass
            else:
                port = 6379
            redisattacks.redis_rce(target, port)

        # Redis File Enumeration Check
        if args['filecheck']:
            filename = args['filecheck']
            if port:
                pass
            else:
                port = 6379
            redisattacks.redis_file_enum(target, filename, port, creds)

        # Shodan IP Grabber
        if args['shodan']:
            utils.shodan_frame(args['shodan'])

        # Sniffing Module
        if args['sniff'] == 'mongo':
            sniffmongo.sniff_mongo()
        if args['sniff'] == 'redis':
            sniffredis.sniff_redis()
        if args['sniff'] == 'couch':
            sniffcouch.sniff_couch()

        # Clone Database Currently Available for Mongo,Couch and Redis
        if args['clone'] == 'couch':
            couchattacks.clone_couch(target)
        if args['clone'] == 'redis':
            redisattacks.clone_redis(target)
    except KeyboardInterrupt:
        print(colored("[-] Cntrl+C Shutting Down", 'red'))
        sys.exit(0)
