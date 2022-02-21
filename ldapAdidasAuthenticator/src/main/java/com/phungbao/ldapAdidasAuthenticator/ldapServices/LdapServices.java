package com.phungbao.ldapAdidasAuthenticator.ldapServices;

import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.NameAlreadyBoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.InvalidAttributesException;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import com.phungbao.ldapAdidasAuthenticator.ldapConfig.LdapConfig;


public class LdapServices {
	
	private LdapConfig ldapConnection;	// hold the connection to the database
	private DirContext authenticate;	// hold the connection to a single user in the db connection above
	
	// Pass in the port #.  Default is 10389, but safe to assume that other ports can be used
	public LdapServices(int port) {
		ldapConnection = new LdapConfig(port);
		authenticate = null;
	}
	
	/*
	 * Given a singular username input in the format of {domain\\username}
	 * Parse through this input so that we return an array of strings containing a domain and a username
	 * In short, the return value is either a String array of 2 strings or a null String array
	 */
	public String[] extractDomainName(String domainName) {
		// Separate username into 2 parts: domain and username
		// However, if format is invalid, then immediately quit
		// Invalid format examples: abcdefg, \bcefg, abcde\
		int foundSlash = domainName.indexOf("\\");
		if(foundSlash == -1 || foundSlash == 0 || domainName.indexOf(foundSlash) == domainName.length() - 1) {
			System.out.println("Error, (domain\\username) format is invalid!");
			return null;
		}
		
		// Valid format!  use substring twice to store both domain and username and return a list containing these two!
		String domain = domainName.substring(0, foundSlash);
		String username = domainName.substring(foundSlash + 1);
		String[] returnArray = {domain, username};
		return returnArray;
	}
	
	/*
	 * Given a user's login username info in the domain\\username format already split in 2 pieces
	 * Use a filter to join 2 conditions with the AND operator.
	 * Also specify which attributes to retrieve upon a successful filter.
	 * 		In this case, the 2 attributes are the employeeType (domain) and uid (username)
	 */
	public String searchUserDN(String domain, String username) {
		
		// filter both the domain and the username
		String searchFilter = "(&(employeeType=" + domain + ")(uid=" + username + "))";	
		String[] objAttr = {"employeeType", "uid"}; // retrieve the domain name (employee) and the user name (uid)
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);	// Essentially search the entire tree structure down to the leaves
		controls.setReturningAttributes(objAttr);				// and add the list of filtered attributes to retrieve per user
		
		try {
			// Return a list of users who have the same domain and username.
			// In most cases, we only care about the 1 user, so the result SHOULD be unique
			NamingEnumeration<SearchResult> users = ldapConnection.getConnection().search("dc=adidas,dc=com", searchFilter, controls);
			if(users.hasMore()) {
				SearchResult result = (SearchResult) users.next();	// retrieve the first (and hopefully) only user
				Attributes atr = result.getAttributes();			// retrieve all attributes from user defined within objAttr
				
				// To ensure that the user is valid and exists in our LDAP database, 
				// check to see if the found user has the same inputs as what's being stored in the DB
				String retrievedDomain = atr.get(objAttr[0]).get().toString();	
				String retrievedUsername = atr.get(objAttr[1]).get().toString();
				
				// return either the DN as a string or an empty string
				return (retrievedDomain.equals(domain) && retrievedUsername.equals(username)? result.getNameInNamespace() : "");
				
			}
			else {
				return "";
			}
		} 
		catch (Exception e) {
			return "";
		}
	}
	
	/*
	 * Given a domainName in the form of domain\\username (with one of the slashes being an escape character) and a password,
	 * First, parse the domainName into a domain string and a username string
	 * 		if the parsing fails, then the format is wrong, and thus return false.
	 * Second, find the user's Distinguished Name (DN) by searching for it via the helper function searchUserDN(domain, username)
	 * Third, create a new Properties mapping using a port number, the found DN, and the password.
	 * Finally, attempt a connection to the LDAP database using the information gathered.  
	 *		if no exceptions were thrown, then return true.  
	 *		else, return false
	 */
	public boolean authenticateUser(String domainName, String password) {
		// Parse the domain name into two different strings: domain [0] and username [1]
		// If the array returns null, then immediately quit the update
		String[] parsedDomainName = this.extractDomainName(domainName);
		if(parsedDomainName == null) {
			System.out.println("Error, invalid username format.  Please provide the input in the 'domain\\username' format");
			return false;
		}
		
		// Search for the user's DN via the 2 parsed strings above
		String dn = this.searchUserDN(parsedDomainName[0],  parsedDomainName[1]);
		if(dn.equals("")) {
			System.out.println("Error in authenticating user.  They do not exist in the LDAP database.");
			return false;
		}
		
		// Create another Properties object to store a connection to the requested user.
		Properties env = ldapConnection.createEnvironment(10389, dn, password);
		
		try {
			authenticate = new InitialDirContext(env);
			System.out.println("Authentication successful!");
			return true;
		} 
		catch (Exception e) {
			System.out.println("Error in authenticating user, see error below\n" + e.getMessage());
			return false;
		}
	}
	
	/*
	 * Given a valid user, attempt to change their password to a new one.
	 */
	public boolean updateUserPassword(String domainName, String password) {
		
		// Parse the domain name into two different strings.
		// If the array returns null, then immediately quit the update
		String[] parsedDomainName = this.extractDomainName(domainName);
		if(parsedDomainName == null) {
			System.out.println("Error, (domain\\username) format is invalid!");
			return false;
		}
		
		try {
			String dn = this.searchUserDN(parsedDomainName[0], parsedDomainName[1]); // [0] = domain, [1] = username
			if(dn.equals(""))
				throw new AuthenticationException("Error, user does not exist.");
				
			// Create a singular list of ModificationItems to tell the connection what needs to be changed
			ModificationItem[] mods = new ModificationItem[1];
			mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", password));
			ldapConnection.getConnection().modifyAttributes(dn, mods);
			System.out.println("Password for " + domainName + "was successfully changed!");
			return true;
		}
		catch(AuthenticationException e) {
			System.out.println(e.getMessage());
		}
		catch(Exception e) {
			System.out.println("Error in updating user password.  Please see error message below.\n" + e.getMessage());
		}
		return false;
	}
	
	/*
	 * Helper function to generate the uid string via a non-null first and last name
	 */
	private String generateUID(String firstName, String lastName) {
		if(firstName.equals("") || lastName.equals(""))
			return "";
		
		StringBuilder uid = new StringBuilder();
		
		// First, take the first 5 letters of the last name (lowercase if necessary)
		for(int i = 0; i < 5; i++) {
			if(i < lastName.length())
				uid.append(Character.toLowerCase(lastName.charAt(i)));
			else
				break;
		}
		// Second, take the first 3 letters of the first name (lowercase if necessary)
		for(int i = 0; i < 3; i++) {
			if(i < firstName.length())
				uid.append(Character.toLowerCase(firstName.charAt(i)));
			else 
				break;
		}
		
		return uid.toString();
	}
	
	// Add a user to the database, given their domain, first & last name, password
	// By default, add them to the following DN: ou=users,dc=adidas,dc=com.
	public boolean addUser(String domain, String firstName, String lastName, String password) {
		
		// Provide a list of attributes to create for the user.  Begin with no attributes created
		Attributes attributes = new BasicAttributes();
		
		// Most important thing, add the user as an "inetOrgPerson", via the objectClass attribute.
		attributes.put("objectClass", "inetOrgPerson");	
		
		// Add the user's uid and domain.  However, uid will be generated via the helper function "generateUID(first, last)"
		String uid = this.generateUID(firstName, lastName);
		attributes.put("uid", uid);
		attributes.put("employeeType", domain);
		
		// Add the user's required cn and sn fields with first name and last name
		attributes.put("cn", firstName);
		attributes.put("sn", lastName);	
		
		// Finally, add their password
		attributes.put("userPassword", password);
		
		
		// Finally, reference the admin connection to add the above details
		try {
			// Hard code the new DN path, using the uid as the RDN.
			String dn = "uid=" + uid + ",ou=users,dc=adidas,dc=com";
			
			// Creating a connection requires providing the full DN and the list of attributes.  
			// Thus, make the DN as simple as possible.
			ldapConnection.getConnection().createSubcontext(dn, attributes);
			System.out.println("Successfully added " + firstName + " " + lastName + " to the LDAP database.");
			return true;
		} 
		catch(NameAlreadyBoundException e) {
			System.out.println("Error in adding user, the user already exists in the system, see below\n" + e.getMessage());
		}
		catch(InvalidAttributesException e) {
			System.out.println("Error in adding user, not all required attributes were added, see below\n" + e.getMessage());
		}
		catch (NamingException e) {
			System.out.println("Error in adding user, unable to add user to the database, see below\n" + e.getMessage());
		}	
		return false;
	}
	
	/*
	 * Delete a user from the ldap db, given their first and last name, as well as the domain associated with their account.  
	 * Queries via the DN, which can be generated after retrieving both domain and uid.
	 */
	public boolean deleteUser(String domain, String firstName, String lastName) {
		try {
			String uid = this.generateUID(firstName, lastName);
			String dn = this.searchUserDN(domain, uid);
			if(dn.equals(""))
				throw new Exception("User does not exist in the database");
			ldapConnection.getConnection().destroySubcontext(dn);
			System.out.println("Successfully deleted " + firstName + " " + lastName + " from the LDAP database.");
			return true;
		}
		catch(Exception e) {
			System.out.println("Error in deleting user, see error below for more details\n" + e.getMessage());
			return false;
		}
	}
}
