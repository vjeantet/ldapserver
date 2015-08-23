<?php
// $ldap_host = "ldaps://127.0.0.1:10636"; // SSL
$ldap_host = "ldap://127.0.0.1:10389"; // non SSL
$ldap_user  = "myLogin";
$ldap_pass = "pass";

//putenv('LDAPTLS_REQCERT=never');
ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 0);

$ds = ldap_connect($ldap_host) or exit(">>Could not connect to LDAP server<<");
ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

// ldap_start_tls($ds) ; // StartTLS (Only on non SSL)

/* #### ADD ### */
	$login = "login" ;
	echo "\nBind ".$login ;
	ldap_bind($ds,$login,"padfqd3645%+") ;

/* #### ADD ### */
	$dn = "cn=John Jones, o=My Company, c=US" ;
	echo "\nAdd ".$dn ;
	// Prépare les données
	$info["cn"] = "John Jones";
	$info["sn"] = "Jones";
	$info["objectclass"] = "person";
	// Ajoute les données au dossier
	$r = ldap_add($ds, "cn=John Jones, o=My Company, c=US", $info) ;

/* #### MODIFY ENTRIE ### */
	$dn = "cn=myNetCard,ou=Networks,dc=example,dc=com" ;
	echo "\nModify ".$dn ;
	$entry["objectclass"][0] = "device";
	$entry["objectclass"][1] = "ieee802Device"; // add an auxiliary objectclass
	$entry["macAddress"][0] = "aa:bb:cc:dd:ee:ff";

	ldap_modify ($ds, $dn, $entry);


/* #### DELETE ENTRIE ### */
	$dn = "cn=MyDeleter,ou=Networks,dc=example,dc=com" ;
	echo "\nDelete ".$dn ;
	ldap_delete($ds, $dn) ;

/* #### MOD ADD ### */
	$dn = "cn=groupname,cn=groups,dc=example,dc=com";
	echo "\nModAdd ".$dn ;
	$entry['memberuid'] = "username";

	ldap_mod_add($ds, $dn, $entry);

/* #### MOD DELETE ### */
	$dn = "cn=groupname,cn=groups,dc=example,dc=com";
	echo "\nModDel ".$dn ;
	$entry['memberuid'] = "username";

	ldap_mod_del($ds, $dn, $entry);


/* #### MOD REPLACE ### */
	$dn = "cn=groupname,cn=groups,dc=example,dc=com";
	echo "\nModReplace ".$dn ;
	$entry['memberuid'] = "username";

	ldap_mod_replace($ds, $dn, $entry);

/* ### SEARCH ### */
	$dn = "o=My Company, c=USs";
	echo "\nSearch ".$dn ;
	$filter="(|(sn=jeantet)(givenname=jeantet*))";
	$justthese = array("ou", "sn", "givenname", "mail");
	$cookie = 'cookie';
    ldap_control_paged_result($ds, 23, true, $cookie);
	$sr=ldap_search($ds, $dn, $filter, $justthese);
	$info = ldap_get_entries($ds, $sr);
	echo "\n\t".$info["count"]." entries returned";
	// ldap_control_paged_result_response($ds, $sr, $cookie);

/* ### COMPARE ### */
	$dn = "cn=Matti Meikku, ou=My Unit, o=My Company, c=FI";
	echo "\nCompare ".$dn ;
	// Préparation des données
	
	$value = "secretpassword";
	$attr = "password";
	// Comparaison des valeurs
	$r=ldap_compare($ds, $dn, $attr, $value);
	if ($r === -1) {
	    echo "Error: " . ldap_error($ds);
	} elseif ($r === true) {
	    echo "\n\tCompare true.";
	} elseif ($r === false) {
	    echo "\n\tCompare false !";
	}


/* ### LDAP CLOSE / UNBIND ### */
	
	echo "\nUnbind " ;
	ldap_unbind($ds) ;


echo "\n" ;
