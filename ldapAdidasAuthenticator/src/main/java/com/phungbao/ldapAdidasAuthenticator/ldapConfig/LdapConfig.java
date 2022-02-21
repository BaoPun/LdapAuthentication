package com.phungbao.ldapAdidasAuthenticator.ldapConfig;

import java.util.Hashtable;
import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LdapConfig {
	
	// Hold the DirContext object to store the LDAP database connection (assuming it was successful)
	private DirContext connection;
	
	// The constructor 
	public LdapConfig(int port) {
		if(!this.createNewConnection(port)) {
			System.out.println("Error, connection to database failed.  Exiting the program.");
			System.exit(1);
		}
	}
	
	// Set up the Properties of the connection here.
	// specify the port #, the distinguished name of the user (DN), and the associated password
	public Properties createEnvironment(int port, String dn, String password) {
		Properties environment = new Properties();
		environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");	// path given for ldap using jdni
		environment.put(Context.PROVIDER_URL, "ldap://localhost:" + Integer.toString(port));	// provide the port #
		environment.put(Context.SECURITY_AUTHENTICATION, "simple");								// what type of authentication
		environment.put(Context.SECURITY_PRINCIPAL, dn);										// username in DN form
		environment.put(Context.SECURITY_CREDENTIALS, password);								// password
		return environment;
	}
	
	// Attempt to log into the db database using ADMIN credentials
	// Return true if connection was successful, and false otherwise.
	private boolean createNewConnection(int port) {
		// Set up the connection
		Properties env = this.createEnvironment(port, "uid=admin,ou=system", "secret");
		
		try {
			// If this object doesn't catch an exception, then the connection was successful!
			connection = new InitialDirContext(env);
			return true;
		}
		// If Bind DN or user is invalid, then this gets caught
		catch(AuthenticationException e) {	
			System.out.println("Connection failed, see below error\n" + e.getMessage());
		}
		// if password doesn't match, then this gets caught
		catch(NamingException e) {			
			System.out.println("Connection failed, see below error\n" + e.getMessage());
		}
		return false;
	}
	
	public DirContext getConnection() {
		return this.connection;
	}
	
	
}
