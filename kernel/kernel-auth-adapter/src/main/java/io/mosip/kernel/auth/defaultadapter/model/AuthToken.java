package io.mosip.kernel.auth.defaultadapter.model;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/***********************************************************************************************************************
 * AUTH_TOKEN USED TO ACCESS TOKEN DETAILS
 *
 * @author Sabbu Uday Kumar
 * @since 1.0.0
 **********************************************************************************************************************/

public class AuthToken extends UsernamePasswordAuthenticationToken {

	private static final long serialVersionUID = 4068560701182593212L;

	private String token;

	private String idToken;

	public AuthToken(String token) {
		super(null, null);
		this.token = token;
	}

	public AuthToken(String token, String idToken){
		super(null, null);
		this.token = token;
		this.idToken = idToken;
	}

	public String getIdToken() {
		return idToken;
	}

	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
}