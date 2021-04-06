# Example configs for AD and Ldap with sssd

These example configs are for an active directory realm using a bluepages ldap server
Read through each file and ensure the settings are configured correctly for your realm, or change them

You can then run the ```join_domain``` script 

Note that by default all users will be granted access to the system if their shell is bash ans they exist in bluepages

Consider pam_access as a mechanism to restruct user access

