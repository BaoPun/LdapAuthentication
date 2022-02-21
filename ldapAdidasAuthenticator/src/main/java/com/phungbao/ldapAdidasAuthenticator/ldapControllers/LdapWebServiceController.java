package com.phungbao.ldapAdidasAuthenticator.ldapControllers;

import java.net.URI;
import java.util.Enumeration;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpSession;


@Controller
public class LdapWebServiceController {
	
	// Map to the home page
	@GetMapping("/")
	public String index() {
		return "index.html";
	}
	
	
	// Map to the success page when login is done and credentials are valid
	@GetMapping("/loginSuccess")
	public String loginSuccessNotification() {
		return "templates/loginSuccess.html";
	}
	
	// Map to the failure page when login is done and credentials are invalid
	@GetMapping("/loginFailure")
	public String loginFailureNotification(Model model) {
		return "templates/loginFailure.html";
	}
}
