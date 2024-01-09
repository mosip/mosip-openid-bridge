package io.mosip.kernel.authcodeflowproxy.api.service;

import io.mosip.kernel.openid.bridge.api.service.LoginService;

/**
 * @author Aravindhan A
 *
 */
public interface LoginServiceV2 extends LoginService{

	String loginV2(String redirectURI, String state, String uiLocales);

}
