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


# https://serverfault.com/q/885324
def get_smb_user_sid(uid):
    sid = config["samba"].get("sid")
    smbuid = int(uid) * 2 + 1000
    return f"{sid}-{smbuid}"


config = configparser.ConfigParser()
config.read(['/etc/bluepages.cfg', os.path.expanduser('~/.bluepages.cfg'), './bluepages.cfg'])

description="A script to export the bp database to yp/ldap."
parser = argparse.ArgumentParser(description=description)
parser.add_argument('-d', '--db', metavar="DATABASE",
        default=config.get('global', 'db', fallback='bp.db'))
parser.add_argument('-p', '--passwd', metavar="FILE", 
        default=config.get('global', 'passwd', fallback='passwd'))
parser.add_argument('-g', '--group', metavar="FILE",
        default=config.get('global', 'group', fallback='group'))
parser.add_argument('-v', '--verbose', action="store_true")
args = parser.parse_args()

if not os.path.exists(args.db):
    print("ERROR: File %s not found!" % (args.db))
    sys.exit(1)

try:
    con = sqlite3.connect(args.db)
except:
    print("ERROR: Could not open database %s" % (args.db))
    sys.exit(2)
cur = con.cursor()


directory = False
previous_ldap_users = {}
previous_ldap_groups = {}
if 'ldap' in config:
    # connect to the directory.
    if config["ldap"].get("tls_reqcert"):
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    directory = ldap.initialize(f"{config['ldap']['uri']}")
    directory.simple_bind_s(config['ldap']['binddn'],
                    config['ldap']['bindpw'])

    # list any existing users. We will use this to match against 
    # users as we process the bp user database so we know whether
    # to create a new ldap user or update an existing one. As entries
    # are matched we remove them from this dictionary - any users 
    # left at the end are removed from ldap.
    criteria = "(objectClass=posixAccount)"
    results = directory.search_s(config['ldap']['users_ou'],
            ldap.SCOPE_SUBTREE, criteria)

    for (dn, attrs) in results:
        previous_ldap_users[dn] = attrs


    # list any existing groups - same process as with the users
    criteria = '(objectClass=posixGroup)'
    results = directory.search_s(config['ldap']['groups_ou'],
            ldap.SCOPE_SUBTREE, criteria)

    for (dn, attrs) in results:
        previous_ldap_groups[dn] = attrs

samba = False
user_object_class = [b'top', b'person', b'organizationalPerson', b'inetorgperson', b'posixAccount']
if 'samba' in config:
    samba = True
    user_object_class = [b'top', b'person', b'organizationalPerson', b'inetorgperson', b'posixAccount', b'sambaSamAccount']



# get all users who are not inactive or disabled. 
sql="""SELECT * FROM passwd 
  WHERE status NOT IN ('inactive', 'disabled')
  ORDER BY name ASC"""

# keep a record of the users for matching against the group memberships
# the key is the AD username, and the value is the linux username
valid_user_map = {}

with open(args.passwd, 'w') as f:
    for r in cur.execute(sql):
        user = dict(zip([c[0] for c in cur.description], r))

        if args.verbose:
            print(f"Adding user {user['name']}")

        valid_user_map[user['sAMAccountName']] = user['name']

        f.write("%s:%s:%s:%s:%s:%s:%s\n" % (user['name'],
            user['password'], user['UID'], user['GID'], user['GECOS'], 
            user['directory'], user['shell']))

        if directory:
            # create DN for new user
            user_dn = f"uid={user['name']},{config['ldap']['users_ou']}"
            gecos = user['GECOS']
            if "" == gecos:
               gecos = user['name']
            attrs = {}
            attrs['objectClass'] = user_object_class
            attrs['cn'] = [user['name'].encode()]
            attrs['uid'] = [user['name'].encode()]
            attrs['sn'] = [user['sn'].encode()]
            attrs['givenName'] = [user['givenName'].encode()]
            attrs['uidNumber'] = [user['UID'].encode()]
            attrs['gidNumber'] = [user['GID'].encode()]
            attrs['loginShell'] = [user['shell'].encode()]
            attrs['homeDirectory'] = [user['directory'].encode()]
            attrs['gecos'] = [gecos.encode()]

            if samba:
                attrs['sambaSID'] = [get_smb_user_sid(user['UID']).encode()]

            # create or update user ldap entry
            if user_dn in previous_ldap_users:
                mod = ldap.modlist.modifyModlist(previous_ldap_users[user_dn], attrs)
                directory.modify_s(user_dn, mod)
                del previous_ldap_users[user_dn]
            else:
                mod = ldap.modlist.addModlist(attrs)
                directory.add_s(user_dn, mod)


sql="""SELECT name, GID, user_list
  FROM grp
  ORDER BY name ASC"""

with open(args.group, 'w') as f:

    # We want to avoid the length of any line of the group file being
    # more than 1024 characters. The default max entry length of 924
    # characters means 100 characters are allowed for the other fields
    max_entry_length = int(config.get('DEFAULT', 'max_entry_length',
            fallback='924'))

    for r in cur.execute(sql):
        group = dict(zip([c[0] for c in cur.description], r))
    
        # the user list is stored in the database in json
        ad_user_list = json.loads(group['user_list'])

        # Build a list of LINUX usernames for the group membership.
        # Users which aren't published to the passwd file will be excluded
        # at this point
        user_list = []
        for aduser in ad_user_list:
            if aduser in valid_user_map:
                user_list.append(valid_user_map[aduser])

        # sort the list so that we print the entries sorted in the group file
        user_list.sort()

        if user_list:
            if args.verbose:
                print(f"Adding group {group['name']}")

            # split the user list into slices, a new slice is begun if adding 
            # another item would push it beyond the maximum entry length
            s = 0
            user_list_slices = collections.defaultdict(list)
            for user in user_list:
                if len(",".join(user_list_slices[s]))+len(user)+1 > max_entry_length:
                    s += 1
                user_list_slices[s].append(user)

            # loop over the slices sorted in descending order, so that the 
            # 'real' group name is printed last.
            for (i, users) in sorted(user_list_slices.items(), reverse=True):
                if i == 0:
                    name = group['name']
                else:
                    name = f"{group['name']}_{i}"

                if args.verbose and i == 1:
                    print(f"Entries for group {group['name']} have exceeded the maximum length and will be split.")

                f.write("%s:%s:%s:%s\n" % (name, 'x', group['GID'], ",".join(users)))

        else:
            if args.verbose:
                print(f"Adding empty group {group['name']}")

            f.write("%s:%s:%s:\n" % (group['name'],
                'x', group['GID']))


        if directory:
            group_dn = f"cn={group['name']},{config['ldap']['groups_ou']}"
            attrs = {}
            attrs['objectClass'] = [b'top', b'groupOfUniqueNames', b'posixGroup']
            attrs['cn'] = [group['name'].encode()]
            attrs['gidNumber'] = [group['GID'].encode()]
            if user_list:
                attrs['uniqueMember'] = []
                for user in user_list:
                    user_dn = f"uid={user},{config['ldap']['users_ou']}"
                    attrs['uniqueMember'].append(user_dn.encode())

            # create or modify the group
            if group_dn in previous_ldap_groups:
                mod = ldap.modlist.modifyModlist(previous_ldap_groups[group_dn], attrs)
                directory.modify_s(group_dn, mod)
                del previous_ldap_groups[group_dn]
            else:
                mod = ldap.modlist.addModlist(attrs)
                directory.add_s(group_dn, mod)


# any user or group DNs that are still in the set captured at the start
# must be ones we didn't match against current bp so drop these
if directory:
    for dn in previous_ldap_users:
        print(f"Removing ldap entry {dn} as there was no corresponding bp entry matched")
        directory.delete_s(dn)

    for dn in previous_ldap_groups:
        print(f"Removing ldap entry {dn} as there was no corresponding bp entry matched")
        directory.delete_s(dn)    

# close sqlite database connection
con.close()
