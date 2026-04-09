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
		String token = getValidToken();
		request.getHeaders().set(AuthAdapterConstant.AUTH_HEADER_COOKIE,
				AuthAdapterConstant.AUTH_HEADER + token);

		// Execute the actual request
		ClientHttpResponse response = execution.execute(request, body);

		// Handle token expiration gracefully (only on 401)
		if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
			LOGGER.warn("Received 401 Unauthorized. Attempting token refresh.");

			synchronized (this) {
				// Double-check after acquiring lock
				if (!isTokenValid(cachedToken.getToken())) {
					String newToken = tokenHelper.getClientToken(clientID, clientSecret, appID, restTemplate);
					if (Objects.isNull(newToken)) {
						LOGGER.error("Failed to obtain new auth token from IAM");
						throw new AuthAdapterException(AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorCode(),
								AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorMessage());
					}
					cachedToken.setToken(newToken);
					LOGGER.info("Successfully refreshed auth token");
				}
			}

			// Re-execute request with fresh token
			addAuthTokenToHeader(request, cachedToken.getToken());
			return execution.execute(request, body);
		}

		return response;
	}

	// Clean and efficient way to handle other cookies
	private void addAuthTokenToHeader(HttpRequest request, String token) {
		List<String> existingCookies = request.getHeaders().get(AuthAdapterConstant.AUTH_HEADER_COOKIE);

		// If no cookies exist or only auth-related, just set the new one
		if (existingCookies == null || existingCookies.isEmpty()) {
			request.getHeaders().set(AuthAdapterConstant.AUTH_HEADER_COOKIE,
					AuthAdapterConstant.AUTH_HEADER + token);
			return;
		}

		// Remove only the old auth token entries, keep other cookies
		List<String> cleanedCookies = existingCookies.stream()
				.filter(cookie -> !cookie.contains(AuthAdapterConstant.AUTH_HEADER))
				.collect(Collectors.toList());

		// Add the new auth token
		cleanedCookies.add(AuthAdapterConstant.AUTH_HEADER + token);

		// Replace with cleaned + new token
		request.getHeaders().replace(AuthAdapterConstant.AUTH_HEADER_COOKIE, cleanedCookies);
	}

	/**
	 * Returns a valid token with minimal synchronization.
	 * This is the hot path called on every request.
	 */
	private String getValidToken() {
		String token = cachedToken.getToken();

		// Fast path - token exists and appears valid
		if (token != null) {
			return token;
		}

		// Token is missing or invalid - need to refresh (rare after initial setup)
		synchronized (this) {
			token = cachedToken.getToken();
			if (token == null || !isTokenValid(token)) {
				LOGGER.info("Fetching new auth token for client: {}", clientID);

				String newToken = tokenHelper.getClientToken(clientID, clientSecret, appID, restTemplate);
				if (Objects.isNull(newToken)) {
					LOGGER.error("there is some issue with getting token with clienid and secret");
					throw new AuthAdapterException(AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorCode(),
							AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorMessage());
				}
				cachedToken.setToken(newToken);
				return newToken;
			}
			return cachedToken.getToken();
		}
	}

	// Updated to use common code to validate the token online.
	private boolean isTokenValid(String authToken) {
		return Objects.nonNull(tokenValidationHelper.getOnlineTokenValidatedUserResponse(authToken, restTemplate));
	}
}
