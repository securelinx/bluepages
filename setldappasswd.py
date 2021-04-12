#!/usr/bin/env python3

#
# convert a sqlite database to yp/ldap
#

import argparse
import configparser
import sqlite3
import sys
import os
import json
import collections
import ldap, ldap.modlist
from getpass import getpass


config = configparser.ConfigParser()
config.read(['/etc/bluepages.cfg', os.path.expanduser('~/.bluepages.cfg'), './bluepages.cfg'])

description="A script to export the bp database to yp/ldap."
parser = argparse.ArgumentParser(description=description)
parser.add_argument('-v', '--verbose', action="store_true")
parser.add_argument('username',
        help='The user name in the identity provider to operate on' )
args = parser.parse_args()


previous_ldap_users = {}
l = False
if 'ldap' in config:
    # connect to the directory.
    if config["ldap"].get("tls_reqcert"):
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    l = ldap.initialize(f"{config['ldap']['uri']}")
    l.set_option(ldap.OPT_REFERRALS, 0)
    l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    l.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
    l.set_option( ldap.OPT_X_TLS_DEMAND, True )
    l.set_option( ldap.OPT_DEBUG_LEVEL, 255 )
#    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    l.simple_bind_s(config['ldap']['binddn'],
                    config['ldap']['bindpw'])

   # l.set_option( ldap.OPT_X_TLS_DEMAND, True )
   # l.set_option( ldap.OPT_DEBUG_LEVEL, 255 )
    # list any existing users. We will use this to match against 
    # users as we process the bp user database so we know whether
    # to create a new ldap user or update an existing one. As entries
    # are matched we remove them from this dictionary - any users 
    # left at the end are removed from ldap.
    criteria = "(objectClass=posixAccount)"
    results = l.search_s(config['ldap']['users_ou'],
            ldap.SCOPE_SUBTREE, criteria)


    if l:
        
        for (dn, attrs) in results:
           previous_ldap_users[dn] = attrs

        # Work out DN for new user
        user_dn = f"uid={args.username},{config['ldap']['users_ou']}"

        # create or update user ldap entry
        if user_dn in previous_ldap_users:
            print ( "found %s" % args.username )
            password=None
            password_conf="not a password"
            while password_conf != password:
                password = getpass  ("Enter password:" )
                password_conf = getpass  ("Confirm:" )


                if password_conf != password:
                   print ("Passwords do not match")
                else:
                   l.passwd_s(user_dn, None, password)
               
        else:
            print ( "User %s notfound" % args.username )

