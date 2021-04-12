#!/usr/bin/env python3

#
# Add newly discovered users to sqlite database
#

import argparse
import configparser
import sqlite3
import sys
import os
import ldap
import struct
import json
import re

def sid2string(binary):
    """Return a string representation of a SID
    when given the binary format.
    https://stackoverflow.com/a/52825313
    """
    version = struct.unpack('B', binary[0:1])[0]
    # I do not know how to treat version != 1 (it does not exist yet)
    assert version == 1, version
    length = struct.unpack('B', binary[1:2])[0]
    authority = struct.unpack(b'>Q', b'\x00\x00' + binary[2:8])[0]
    string = 'S-%d-%d' % (version, authority)
    binary = binary[8:]
    assert len(binary) == 4 * length
    for i in range(length):
        value = struct.unpack('<L', binary[4*i:4*(i+1)])[0]
        string += '-%d' % value
    return string


def sid2uid(sid):
    """
    Return a UID number for a user when supplied with a SID
    This is a two step process

    1. Find the RID part of the SID (this is the last part of the string)
    https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253

    2. Add the rid to the offset for the domain, attempting to emulate
    the process performed by sssd.
    """
    sidstring = sid2string(sid)

    # get the last part of the SID string, the rid
    rid = sidstring.split('-')[7]

    # return the rid plus the offset
    offset = int(config.get('directory', 'sid_offset', fallback=200000))
    return offset + int(rid)


def is_unique_uid(uid, users):
    """
    Return False (not unique) if the suppiled UID is found in the set 
    of supplied users. Otherwise return True.
    """
    for user in users.values():
        if user['UID'] == str(uid):
            return False

    return True


# Load configuration values
config = configparser.ConfigParser()
config.read(['/etc/bluepages.cfg', os.path.expanduser('~/.bluepages.cfg'), './bluepages.cfg'])

# process arguments
description="A script to add newly discovered users to sqlite database"
parser = argparse.ArgumentParser(description=description)
parser.add_argument('-d', '--db', metavar="DATABASE", 
        default=config.get('global', 'db', fallback='bp.db'))
parser.add_argument('-v', '--verbose', action="store_true")
args = parser.parse_args()

# connect to sqlite database
try:
    con = sqlite3.connect(args.db)
except:
    print("ERROR: Could not open database %s" % (args.db))
    sys.exit(2)
cur = con.cursor()

# create the passwd table if it doesn't exist
cur.execute("""CREATE TABLE IF NOT EXISTS passwd
        (name text NOT NULL PRIMARY KEY,
            sAMAccountName text NOT NULL UNIQUE,
            password text, UID text, GID text, GECOS text,
            directory text, shell text, status text,
            givenName text, sn text)""")

# since the user database is small put the whole thing in a dictionary
# so we can search it. the key is the AD username and the value is a dict
# of all the fields in that row of the database
nis_users = {}
for r in cur.execute("select * from passwd").fetchall():
    user = dict(zip([c[0] for c in cur.description], r))
    nis_users[user['sAMAccountName'].lower()] = user

# set all active users to inactive (so we can then set the ad users
# we find back to active)
cur.execute("update passwd set status = 'inactive' where status = 'active'")

# drop the group table and re-create it
cur.execute("DROP TABLE IF EXISTS grp")
cur.execute("""CREATE TABLE grp
    (name text NOT NULL PRIMARY KEY,
        GID text, user_list text)""")

# connect to the directory if configured. disable referrals.
directory = False
if 'directory' in config:
    directory = ldap.initialize(f"ldap://{config['directory']['dc']}")
    directory.set_option(ldap.OPT_REFERRALS,0)
    attributes = ['sAMAccountName', 'displayName', 'givenName', 'sn', 'objectSid']

    directory.simple_bind_s(config['directory']['binduser'],
            config['directory']['bindpw'])

# loop over each configured group.
for section in config:

    # this is a small hack. what we're actually doing is looping over all
    # the sections of the config, so if this section isn't one that describes
    # a group then skip on to the next one.
    if "group:" not in section:
        continue

    group = config[section]
    if args.verbose:
         print(f"Checking group {group['name']}")

    # by default groups aren't used to provision users it has to be set
    provisioning = group.get('provisioning', False)

    # If there is a dn set for the group then search AD for it. If not just set
    # the results set as empty. This might be more useful in future, but for now 
    # all it lets you do is set a group to exist in NIS which is independent of
    # the directory (but there is no way to add any members)
    if group.get('dn') and directory:
        # set the ldap filter to find users who are members of this group
        # the mad looking numbers are a microsoft rule OID which returns 
        # all members of the group (including those via nested groups)
        # https://docs.microsoft.com/en-gb/windows/win32/adsi/search-filter-syntax
        criteria = f"(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group['dn']}))"

        # search the directory for all users in the group
        results = directory.search_s(config['directory']['dn'], 
                ldap.SCOPE_SUBTREE, criteria, attributes)
    else:
        results = []
        if args.verbose:
            print(f"No dn set for group {group['name']} so not checking directory")

    # need to make a list of all the group members.
    group_members = []
    # add in any from the config file 
    if 'members' in group:
        group_members = group.get('members').split(',')
        # strip any spaces that were between names in the file
        group_members = [name.strip() for name in group_members]

    # loop over all the found directory users
    for (dn, account) in results:

        # microsoft says those filters should be enough to only match 
        # people but it seems other things can still come back so
        # skip over anything that doesn't have an account name
        # (I think this may be to do with referrals??)
        if not 'sAMAccountName' in account:
            continue

        # values come back from ldap as a byte string in a list so 
        # we need to mangle name back into a sane format before we use it
        name = str(account['sAMAccountName'][0], encoding='utf-8').lower()

        # apply some logic here to make sure bad usernames don't get from 
        # the directory into our database. If there's no regex set
        # in the config then just block users called root.
        bad_user_regex = group.get('bad_user_regex', '^root$')
        if re.match(bad_user_regex, name):
            continue

        # add the name to our members for this group
        group_members.append(name)

        # if this isn't a provisioning group then we don't need to bother
        # with any other actions for the user.
        if not provisioning:
            continue

        # where we find a directory user who already has a NIS profile
        # mark it as active
        if name in nis_users:
            cur.execute("""update passwd set status = 'active' where status = 
                'inactive' and sAMAccountName = ?""", (name,))
        # if the user found in the directory is not in NIS then add them
        else: 
            # Try to work out what UID sssd would generate from the user SID
            uid = sid2uid(account['objectSid'][0])

            # If the first UID we calculate is taken then look in the
            # next slices until we find one that is available
            while not is_unique_uid(uid, nis_users):
                uid = uid + int(config.get('directory', 
                    'sid_slice', fallback=20000))

            # we expect most accounts to have a name attributes set
            # but if they don't just re-use the account name
            names = {'displayName': name, 'givenName': name, 'sn': name }
            for field in names:
                if field in account:
                    names[field] = str(account[field][0], encoding='utf-8')

            # build a dict that describes the new user
            basedir = group.get('basedir', '/home')
            user = {'name': name, 
                    'sAMAccountName': name,
                    'password': group.get('password', '!!'),
                    'UID': uid,
                    'GID': group['gid'],
                    'GECOS': names['displayName'],
                    'givenName': names['givenName'],
                    'sn': names['sn'],
                    'directory': f"{basedir}/{name}",
                    'shell':  group.get('shell', '/sbin/nologin'),
                    'status': 'active'}

            print (f"Adding new user {name} ({user['UID']})")

            # add that user to our set in memory 
            # (just used for future loop iterations)
            nis_users[name] = user

            # and put it in the database
            try:
                cur.execute("""INSERT INTO passwd values
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (user['name'],
                            user['sAMAccountName'], user['password'], 
                            user['UID'], user['GID'], user['GECOS'], 
                            user['directory'], user['shell'], user['status'], 
                            user['givenName'], user['sn']))
                        
            except:
                print("WARNING: could not add user %s to database" % user[0])

    # update the group table. we store the list of members as a json
    # so we can process it as a list in later steps.
    cur.execute("INSERT INTO grp VALUES (?, ?, ?)", (group['name'], 
            group['gid'], json.dumps(group_members)))

    if args.verbose:
        print(f"For group {group['name']} found members {group_members}")


con.commit()
con.close()

