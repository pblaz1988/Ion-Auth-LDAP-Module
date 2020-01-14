# CodeIgniter-Ion-Auth-LDAP
Quick and dirty LDAP or Active Directory Authentication Modification for IonAuth

* Tested on PHP5
* Required PHP with LDAP support

Quick and dirty hack, which provides LDAP login support. Functionality is limited and can manifest in non-working applications.

First step - configure ion_auth.php configuration file as follows:

```php
$config['ldap_bindUser'] = 'DC=Company,DC=org';		// bind user (query user) full DN
$config['ldap_pwd'] = 'VeryStrongPassword';	// bind user password 
$config['ldap_baseDN'] = '@company.org';		// base DN
$config['ldap_baseDNForBind'] = 'cn=ldap_query_user,ou=Users,dc=company,dc=org';		// base DN for bind
$config['ldap_ldapZahtevanaGrupa'] = 'CN=group,OU=Groups,DC=Company,DC=org';		// user must be member of this group (full DN string)
$config['ldap_server'] = 'server.company.org';		// ldap server ip or fqdn
```

Second step - add function login_ldap_helper($uname, $pwd) to Ion_auth_model.php

Third step - replace login function.

Classic logon won't work anymore. You would not be able to change user password through Ion Auth.
