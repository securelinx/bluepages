#!/usr/bin/env python3

#
# convert a passwd file format to sqlite database
#

import argparse
import configparser
import sqlite3
import sys
import os

config = configparser.ConfigParser()
config.read(['/etc/bluepages.cfg', os.path.expanduser('~/.bluepages.cfg'), './bluepages.cfg'])

description="A script to convert a passwd file format to sqlite database."
parser = argparse.ArgumentParser(description=description)
parser.add_argument('-d', '--db', metavar="DATABASE",
         default=config.get('global', 'db', fallback='bp.db'))
parser.add_argument('-p', '--passwd', metavar="FILE", 
        default=config.get('global', 'passwd', fallback='/etc/passwd'))
args = parser.parse_args()

if os.path.exists(args.db):
    print("ERROR: File %s already exists! Will not clobber." % (args.db))
    sys.exit(1)

try:
    con = sqlite3.connect(args.db)
except:
    print("ERROR: Could not open database %s" % (args.db))
    sys.exit(2)


cur = con.cursor()

# create the table
cur.execute("""CREATE TABLE passwd
        (name text NOT NULL PRIMARY KEY, 
            sAMAccountName text NOT NULL UNIQUE,
            password text, UID text, GID text, GECOS text,
            directory text, shell text, status text,
            givenName text, sn text)""")

with open(args.passwd) as f:
    for line in f:
        try:
            (name, password, UID, GID, GECOS, directory, shell) = line.rstrip().split(':')
        except:
            print("WARNING: could not parse entry %s" % (line))
            continue

        # by default set all users to inactive
        status = "inactive"

        # set the givenName and sn fields to the same as the username
        # unless it splits (eg firstname.lastname format)
        givenName = name
        sn = name
        try:
            (givenName, sn) = name.title().split('.',1)
        except:
            pass


        try:
            cur.execute("""INSERT INTO passwd values 
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (name, name, 
                            password, UID, GID, GECOS, directory, shell, 
                            status, givenName, sn))
        except:
            print("WARNING: could not add user %s to database" % name)


con.commit()
con.close()
