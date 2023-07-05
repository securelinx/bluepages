# BluePages

BluePages is a set of tools to populate a yp/NIS or LDAP database with user entries generated from Active Directory. A local database is maintained which can be updated regularly (eg via cron) and automatically provision (or deactivate) users based on their current status as members of configured AD groups.


## How to use BluePages

1. Configure your `bluepages.cfg` file based on the included example to configure the details for NIS, AD & LDAP, as well as the AD groups to reference.

1. [Optional] Run the `passwd2db.py` script to import an existing passwd file format to the database as user entries

1. Run `syncbp.py` to update the database by connecting to AD. All user accounts found in the configured _provisioning_ groups will be marked as active, and new user entries will be created where one does not already exist.

1. [Optional] To manually override any parameters for a user in the database use `updatebp.py <username>`. This can update any user attributes which need to be changed from the current values, and these values will be preserved as the database is synced with AD in future. This script can also set the user *status* to _manual_ or _disabled_, meaning that the user entry is always considered active (or inactive) regardless of whether it is found in AD when syncing.

1. Run `exportbp.py` to export the BluePages database to NIS maps for passwd and group, and also update ldap if configured to do so.

1. Repeat steps 3-5 as often as you like

## Configuring Linux systems ##

BluePages is designed to fill the gap between Active Directory provided users and groups and the POSIX attributes required for consistent user and group IDs in a Unix environment where there may be one or more networked filesystems.  The client side configuration should use kerberos against your existing AD for authentication (eg through pam_krb5 or sssd_ad) and LDAP or NIS for identities (eg through directly ldap, sssd_ldap, nis directly or sssd_proxy for NIS).  The reference case uses sssd_ad with sssd_ldap.  For the reference case to work, systems need to be 

1. Joined to the Active Direcory, or you are in posession of an account with domain join and computer creation privs.

1. Able to contact the BluePages LDAP server and have appropriate read access to users and groups

A full worked example for the reference case is provided in examples/sssd_ad_sssd_ldap


