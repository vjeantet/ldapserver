<?php
$ldap_host = "ldap://127.0.0.1:10389";
$ldap_user  = "myLogin";
$ldap_pass = "pass";

//putenv('LDAPTLS_REQCERT=never');
ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 0);

$ds = ldap_connect($ldap_host) or exit(">>Could not connect to LDAP server<<");
ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

   ldap_start_tls($ds) ;


	/* ### SEARCH ### */
	$dn = "";
	$filter="objectclass=*";
	$justthese = array("namingContexts", "subschemaSubentry", "supportedLDAPVersion", "supportedSASLMechanisms", "supportedExtension", "supportedControl", "supportedFeatures", "vendorName", "vendorVersion", "+", "objectClass");
	$sr=ldap_read($ds, $dn, $filter, $justthese);
	
	
	$dn = "o=My Company, c=US";
	$filter="objectclass=*";
	$justthese = array("hasSubordinates", "objectClass");
	$sr=ldap_read($ds, $dn, $filter, $justthese);
	

	$dn = "o=My Company, c=US";
	$filter="objectclass=*";
	// $justthese = array("hasSubordinates", "objectClass");
	$sr=ldap_search($ds, $dn, $filter);
	

	echo "\nWaiting 10s " ;
	sleep(10) ;

/* ### LDAP CLOSE / UNBIND ### */
	echo "\nUnbind " ;
	ldap_unbind($ds) ;


echo "\n" ;
