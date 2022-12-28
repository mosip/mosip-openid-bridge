package io.mosip.kernel.openid.bridge.api.service;

import javax.servlet.http.Cookie;

import io.mosip.kernel.openid.bridge.dto.AccessTokenResponseDTO;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;

public interface LoginService {

	String login(String redirectURI, String state);

	Cookie createCookie(String authCookie);

	Object valdiateToken(String authToken);


	AccessTokenResponseDTO loginRedirect(String state, String sessionState, String code, String stateCookie,
			String redirectURI);

	String logoutUser(String token, String redirectURI);

	Cookie createExpiringCookie();

}
