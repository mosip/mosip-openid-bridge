package io.mosip.kernel.auth.defaultadapter.config;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.exception.AuthAdapterException;
import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.TokenHolder;

/**
 * This class intercepts and renew client token.
 * 
 * @author Urvil Joshi
 *
 */
public class SelfTokenRestInterceptor implements ClientHttpRequestInterceptor {

	private String clientID;

	private String clientSecret;

	private String appID;

	private TokenHolder<String> cachedToken;

	private static final Logger LOGGER = LoggerFactory.getLogger(SelfTokenRestInterceptor.class);

	private RestTemplate restTemplate;
	
	private TokenHelper tokenHelper;

	private TokenValidationHelper tokenValidationHelper;

	public SelfTokenRestInterceptor(Environment environment, RestTemplate restTemplate,
			TokenHolder<String> cachedToken, TokenHelper tokenHelper, TokenValidationHelper tokenValidationHelper,
			String applName) {
		clientID = environment.getProperty("mosip.iam.adapter.clientid." + applName, environment.getProperty("mosip.iam.adapter.clientid", ""));
		clientSecret = environment.getProperty("mosip.iam.adapter.clientsecret." + applName, environment.getProperty("mosip.iam.adapter.clientsecret", ""));
		appID = environment.getProperty("mosip.iam.adapter.appid." + applName, environment.getProperty("mosip.iam.adapter.appid", ""));
		this.cachedToken = cachedToken;
		this.restTemplate = restTemplate;
		this.tokenHelper = tokenHelper;
		this.tokenValidationHelper = tokenValidationHelper;
	}

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
			throws IOException {
		// null check if job is not able to fetch client id secret
		if (cachedToken.getToken() == null) {
			// try requesting new token. Added because IDA need the token before it gets created by the scheduler thread.
            String authToken = tokenHelper.getClientToken(clientID, clientSecret, appID, restTemplate);
			if (Objects.isNull(authToken)) {
				LOGGER.error("there is some issue with getting token with clienid and secret");
				throw new AuthAdapterException(AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorCode(),
						AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorMessage());
			}
			cachedToken.setToken(authToken);
		}
		request.getHeaders().add(AuthAdapterConstant.AUTH_HEADER_COOKIE,
				AuthAdapterConstant.AUTH_HEADER + cachedToken.getToken());

		ClientHttpResponse clientHttpResponse = execution.execute(request, body);
		if(clientHttpResponse.getStatusCode() != HttpStatus.UNAUTHORIZED) {
			return clientHttpResponse;
		}
		
		synchronized (this) {
			// online validation
			if(!isTokenValid(cachedToken.getToken())) {
				String authToken = tokenHelper.getClientToken(clientID, clientSecret, appID, restTemplate);
				cachedToken.setToken(authToken);		
			}
		}
		
		List<String> cookies = request.getHeaders().get(AuthAdapterConstant.AUTH_HEADER_COOKIE);
		if (cookies != null && !cookies.isEmpty()) {
			cookies=cookies.stream().filter(str -> !str.contains(AuthAdapterConstant.AUTH_HEADER)).collect(Collectors.toList());
		}
		request.getHeaders().replace(AuthAdapterConstant.AUTH_HEADER_COOKIE, cookies);
		request.getHeaders().add(AuthAdapterConstant.AUTH_HEADER_COOKIE,
				AuthAdapterConstant.AUTH_HEADER + cachedToken.getToken());
		return execution.execute(request, body);

	}

	// Updated to use common code to validate the token online.
	private boolean isTokenValid(String authToken) {
		return Objects.nonNull(tokenValidationHelper.getOnlineTokenValidatedUserResponse(authToken, restTemplate));
	}
}
