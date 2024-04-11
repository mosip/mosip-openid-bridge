package io.mosip.kernel.openid.bridge.api.service;


import io.mosip.kernel.openid.bridge.dto.AccessTokenResponseDTO;
import jakarta.servlet.http.Cookie;

public interface LoginService {

	String login(String redirectURI, String state);

	Cookie createCookie(String authCookie);

	Object valdiateToken(String authToken);


	AccessTokenResponseDTO loginRedirect(String state, String sessionState, String code, String stateCookie,
			String redirectURI);

	String logoutUser(String token, String redirectURI);

	Cookie createExpiringCookie();

}
