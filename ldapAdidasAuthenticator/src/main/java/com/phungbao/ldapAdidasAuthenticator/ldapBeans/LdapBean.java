package com.phungbao.ldapAdidasAuthenticator.ldapBeans;

import org.springframework.http.MediaType;

public class LdapBean {
	// same as the inputs from the login screen
	private String domainUsername;
	private String password;
	
	public LdapBean(String domainUsername, String password) {
		this.domainUsername = domainUsername;
		this.password = password;
	}
	
	public String getDomainUsername() {
		return this.domainUsername;
	}
	
	public void setDomainUsername(String domainUsername) {
		this.domainUsername = domainUsername;
	}
	
	public String getPassword() {
		return this.password;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
	
	
}

// consumes= {MediaType.APPLICATION_FORM_URLENCODED_VALUE}