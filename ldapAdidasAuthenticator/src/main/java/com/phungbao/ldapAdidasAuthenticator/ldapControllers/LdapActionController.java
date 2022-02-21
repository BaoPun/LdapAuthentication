package com.phungbao.ldapAdidasAuthenticator.ldapControllers;

import java.net.URI;

import org.apache.commons.logging.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.phungbao.ldapAdidasAuthenticator.ldapBeans.LdapBean;
import com.phungbao.ldapAdidasAuthenticator.ldapServices.LdapServices;

import jakarta.servlet.http.HttpSession;


@RestController
public class LdapActionController {
	
	private LdapServices services;
	
	
	@PostMapping(value="/login", consumes=MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<String> confirmLoginCredentials(HttpSession session, @RequestParam MultiValueMap<String, String> paramMap){
		// First, retrieve the 2 inputs from the website.
		String domainUsername = paramMap.getFirst("domainUsername");//bean.getDomainUsername();//
		String password = paramMap.getFirst("password");//bean.getPassword();//paramMap.getFirst("password");
		
		// Debug purposes: print them out to the console
		System.out.println("Username: " + domainUsername);
		System.out.println("Password: " + password);
		
		// Second, create a new URI based on the success or failure of the login info, by instantiating a HtppHeaders object
		HttpHeaders headers = new HttpHeaders();
		
		// Here, log onto the DB and try to log in.
		services = new LdapServices(10389);	// default port is 10389
		boolean loginResult = services.authenticateUser(domainUsername, password);
		System.out.println("Did the login succeed? " + loginResult);
		
		if(loginResult)
			headers.setLocation(URI.create("/loginSuccess"));
		else {
			headers.setLocation(URI.create("/loginFailure"));
			
			// Write the failure message
			
		}
		
		return new ResponseEntity<String>(headers, HttpStatus.FOUND);
	}
}
