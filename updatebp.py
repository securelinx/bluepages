#!/usr/bin/env python3

#
# update the bluepages database
#

import argparse
import configparser
import sqlite3
import sys
import os
import distutils.util

def pick_uid(cur):
    """
    Pick the first free uid from a 'manual' range, which is defined as the 
    slice below the one set for the domain users
    """

    offset = int(config.get('directory', 'sid_offset', fallback=400000))
    slice = int(config.get('directory', 'sid_slice', fallback=200000))

    uid = offset - slice + 1
    while cur.execute("select UID from passwd where uid = ?", (uid, )).fetchone():
        uid += 1

    return str(uid)

def validate(entry, field):
    """Do some very very basic valdation of the input for the user fields"""
    if field in ['UID', 'GID']:
        try:
            int(entry)
        except ValueError:
            print(f"The {field} field must be a number")
            return False

    if field in ["name", "sAMAccountName"]:
        # need some new validation here now that username tracking with AD is improved
        return True
    elif field == "password":
        locked_passwords = ['!', '!!', '*']
        if entry not in locked_passwords:
            return confirm(f"Usual password values are {locked_passwords}. Are you sure you want to set {entry}?", "no")
    elif field == "directory":
        if not os.path.isdir(entry):
            return confirm(f"The directory {entry} does not seem to exist? Are you sure?", "yes")
    elif field == "shell":
        if not os.path.isfile(entry):
            return confirm(f"The file {entry} does not seem to exist? Are you sure?", "yes")        
    elif field == "status":
        statuses = ['active', 'inactive', 'manual', 'disabled']
        if entry not in statuses:
            print(f"Allowed status types are {statuses}")
            return False

    return True

def confirm(question, default='yes'):
    """Prompts user for yes/no confirmation and returns True or 
    False based on the input. Loops forever until some valid input.
    """

    if default is None:
        prompt = " [y/n] "
    elif default == 'yes':
        prompt = " [Y/n] "
    elif default == 'no':
        prompt = " [y/N] "
    else:
        raise ValueError(f"Unknown setting '{default}' for default.")

    while True:
        try:
            resp = input(question + prompt).strip().lower() or default
            return distutils.util.strtobool(resp)
        except ValueError:
            return confirm("Please respond with 'yes' or 'no'")


config = configparser.ConfigParser()
config.read(['/etc/bluepages.cfg', os.path.expanduser('~/.bluepages.cfg'), './bluepages.cfg'])

description="A script to update a user in the bluepages sqlite database."
parser = argparse.ArgumentParser(description=description)
parser.add_argument('-d', '--db', metavar="DATABASE", 
        default=config.get('global', 'db', fallback='bp.db'), 
        help='File path to the blue pages database file')
parser.add_argument('--delete', action="store_true")
parser.add_argument('-s', '--status',  default=None, help='change the user status')
parser.add_argument('-v', '--verbose', action="store_true")
parser.add_argument('username', 
        help='The user name in the identity provider to operate on' )
parser.add_argument('-b', '--batchmode', action="store_true", 
        help='Run unattended and accept default values')
args = parser.parse_args()

if not os.path.exists(args.db):
    print("ERROR: File %s not found!" % (args.db))
    sys.exit(1)

if args.batchmode:
   print ( "Running in batch mode")

try:
    con = sqlite3.connect(args.db)
except:
    print("ERROR: Could not open database %s" % (args.db))
    sys.exit(2)
cur = con.cursor()


# search database to see if username parameter refers to an existing user
sql="""SELECT * FROM passwd WHERE name = ?"""
r =  cur.execute(sql, (args.username, )).fetchone()

if r:
    if args.delete:
        print("If you delete a user who exists still in AD they will be re-created!")
        print("In most cases setting the user status to disabled will be more useful")
        if args.batchmode or confirm(f"Are you really sure you want to delete {args.username}?", "no"):
            sql="""DELETE FROM passwd WHERE name = ?"""
            cur.execute(sql, (args.username, ))
            con.commit()
            con.close()
        sys.exit(0)

    user = dict(zip([c[0] for c in cur.description], r))

else:
    if args.delete:
        print(f"ERROR: Could not find user {args.username}")
        sys.exit(1)
    print(f"Could not find existing entry for {args.username}, proceeding will create a new entry.")
    if args.status:
         status = args.status
    else:
         status = 'manual'
    # find the config file block for the default group,
    # whatever that happens to be.
    group = config['DEFAULT']
    
    for section in config:
        if "group:" not in section:
            continue
        group = config[section]
        try:
           if distutils.util.strtobool ( config[section].get('default_group') ) :
               break
        except: 
           pass
       
    
    # Set a default home directory base
    basehome = group.get('basedir', '/home')

    # set the givenName and sn fields to the same as the username
    # unless it splits (eg firstname.lastname format)
    givenName = args.username
    sn = args.username
    try:
        (givenName, sn) = args.username.title().split('.',1)
    except:
        pass

    # build a dict with some defaults for a new user    
    user = {'name': args.username,
            'sAMAccountName': args.username,
            'password': "!!",
            'UID': pick_uid(cur),
            'GID': group.get('gid', '99'),
            'GECOS': " ".join( (givenName,  sn)  ),
            'givenName': givenName,
            'sn': sn,
            'directory': os.path.join( basehome, args.username ),
            'shell': group.get('shell', '/sbin/nologin'),
            'status': status }


# Read any command line parameters to override default or those set
if args.status:
    user['status'] = args.status

# for all the fields that exist for the user step through these 
# so values can be set
user_fields = ['name', 'sAMAccountName', 'password', 'UID', 'GID', 'GECOS', 
  'givenName', 'sn', 'directory', 'shell', 'status']


for field in user_fields:
    valid = False
    while not valid and not args.batchmode:
        entry = input(f"{field} [{user[field]}]: ") or user[field]
        valid = validate(entry, field)
        if valid:
            user[field] = entry

print("")
for field in user_fields:
    print(f"{field:>14}: {user[field]}")
print("")

if not args.batchmode and not confirm("Are you sure you want to update bluepage database with these values?"):
    sys.exit(0)

# delete any previous entry for this user. use the supplied username
# in case we are renaming a user in this process
sql="""DELETE FROM passwd WHERE name = ?"""
cur.execute(sql, (args.username, ))

# put the new values in the database
cur.execute("""INSERT INTO passwd values 
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (user['name'], 
            user['sAMAccountName'], user['password'], user['UID'], 
            user['GID'], user['GECOS'], user['directory'], user['shell'], 
            user['status'], user['givenName'], user['sn']))

con.commit()
con.close()
