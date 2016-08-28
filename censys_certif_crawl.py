#!/usr/bin/python

# Use certificate transparancy for OSINT
#  information from censys
#
# Koen Van Impe
#   20160816
#   
# Usage : censys.py myquery
#
# Configuration : see the censys.ini file
#

import sqlite3
import os
import os.path
import sys
import json
import requests
import ConfigParser
import time
from time import gmtime, strftime

# Setup the variables
Config = ConfigParser.ConfigParser()
Config.read("censys.ini")
SQLDB=Config.get("db", "db")
SQLFILE=Config.get("db", "sql-create")
API_URL = Config.get("censys", "url")
API_INDEX = Config.get("censys", "index")
UID = Config.get("censys", "uid")
SECRET = Config.get("censys", "secret")

# Censys Query
if len(sys.argv) <= 1 :
    print "error occurred: No censys filter given"
    print "Run %s censys_filter" % sys.argv[0]
    sys.exit(1)
censys_query = sys.argv[1]

print "0. Starting %s" % strftime("%Y-%m-%d %H:%M:%S", gmtime())

# Remove any old databases
if os.path.isfile(SQLDB):
    os.remove(SQLDB)

# Setup the database
query = open(SQLFILE, 'r').read()
sqlite3.complete_statement(query)
conn = sqlite3.connect(SQLDB)
with conn:
    cur = conn.cursor()
    try:
        # Create the database
        cur.executescript(query)
        print "1. Database %s created." % SQLDB
        res = None

        # Contact the API
        current_page = 1
        fields = [ "parsed.fingerprint_sha256", "parsed.extensions.subject_alt_name.dns_names", "parsed.issuer_dn", "parsed.subject_dn"]
        data = { 'query': censys_query, 'page': current_page, 'fields': fields}
        data = json.dumps(data)
        res = requests.post(API_URL + API_INDEX, data=data, auth=(UID,SECRET))

        # Check if we get a good reply
        if res.status_code != 200:
            print "error occurred: %s" % res.json()["error"]
            sys.exit(1)

        print "2. Received results for query %s" % censys_query
        metadata_pages = res.json()["metadata"]["pages"]
        metadata_count = res.json()["metadata"]["count"]

        print "3. Got %s results in %s pages." % (metadata_count, metadata_pages)

        while current_page <= metadata_pages:
            if res is None:
                data = { 'query': censys_query, 'page': current_page, 'fields': fields}
                data = json.dumps(data)
                res = requests.post(API_URL + API_INDEX, data=data, auth=(UID,SECRET))

            print "4. Page %s / %s " % (current_page, metadata_pages)

            if "results" in res.json():
                results = res.json()["results"]

                for cert in results:
                    if "parsed.extensions.subject_alt_name.dns_names" in cert:
                        dns_names = cert["parsed.extensions.subject_alt_name.dns_names"]
                        dns_names_count = len(dns_names)
                    else:
                        dns_names = None
                        dns_names_count = 0

                    subject_dn = cert["parsed.subject_dn"][0]
                    issuer_dn = cert["parsed.issuer_dn"][0]
                    fingerprint_sha256 = cert["parsed.fingerprint_sha256"][0]

                    issuer_dn_split = issuer_dn.split(",")
                    issuer_c = ""
                    issuer_o = ""
                    issuer_cn = ""
                    issuer_ou = ""
                    for el in issuer_dn_split:
                        el = el.strip()
                        if el[0:2] == "C=":
                            issuer_c = el[2:]
                        elif el[0:2] == "O=":
                            issuer_o =  el[2:]
                        elif el[0:3] == "CN=":
                            issuer_cn = el[3:]
                        elif el[0:3] == "OU=":
                            issuer_ou = el[3:]

                    subject_dn_split = subject_dn.split(",")
                    subject_c = ""
                    subject_o = ""
                    subject_cn = ""
                    subject_ou = ""
                    for el in subject_dn_split:
                        el = el.strip()
                        if el[0:2] == "C=":
                            subject_c = el[2:]
                        elif el[0:2] == "O=":
                            subject_o =  el[2:]
                        elif el[0:3] == "CN=":
                            subject_cn = el[3:]
                        elif el[0:3] == "OU=":
                            subject_ou = el[3:]

                    subject_dn_table = [ fingerprint_sha256, subject_dn, dns_names_count, subject_c, subject_ou, subject_o, subject_cn]
                    cur.execute("INSERT INTO subject_dn VALUES(?, ?, ?, ?, ?, ?, ?)", subject_dn_table)

                    issuer_dn_table = [ fingerprint_sha256, issuer_dn, issuer_c, issuer_ou, issuer_o, issuer_cn]
                    cur.execute("INSERT INTO issuer_dn VALUES(?, ?, ?, ?, ?, ?)", issuer_dn_table)

                    if dns_names is not None:
                        for name in dns_names:
                            dns_names_table = [ fingerprint_sha256, name ]
                            cur.execute("INSERT INTO dns_names VALUES(?, ?)", dns_names_table)

                conn.commit()
                current_page += 1 
                res = None
                time.sleep(2)

        cur.close()

    except Exception as e:    
        cur.close()
        raise
