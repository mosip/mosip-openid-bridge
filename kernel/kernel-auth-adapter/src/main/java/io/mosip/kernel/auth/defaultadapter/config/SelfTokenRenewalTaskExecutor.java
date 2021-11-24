package io.mosip.kernel.auth.defaultadapter.config;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.web.reactive.function.client.WebClient;

import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.model.TokenHolder;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.util.DateUtils;

public class SelfTokenRenewalTaskExecutor {

	private static final Logger LOGGER = LoggerFactory.getLogger(SelfTokenRenewalTaskExecutor.class);

	private String clientID;

	private String clientSecret;

	private String appID;

	@Value("${mosip.iam.adapter.token-expiry-check-frequency:5}")
	private int tokenExpiryCheckFrequency;
	
	@Value("${mosip.iam.adapter.renewal-before-expiry-interval:5}")
	private int renewalBeforeExpiryInterval;

	@Value("${mosip.iam.adapter.self-token-renewal-enable:true}")
    private boolean isRenewalEnable;

	private TokenHolder<String> cachedTokenObject;

	private TokenHelper tokenHelper;

	private WebClient webClient;

	public SelfTokenRenewalTaskExecutor(TokenHolder<String> cachedTokenObject, WebClient webClient, TokenHelper tokenHelper,
					Environment environment, String applName) {

		this.cachedTokenObject = cachedTokenObject;
		this.webClient = webClient;
		this.tokenHelper = tokenHelper;
		this.clientID = environment.getProperty("mosip.iam.adapter.clientid." + applName, environment.getProperty("mosip.iam.adapter.clientid", ""));
		this.clientSecret = environment.getProperty("mosip.iam.adapter.clientsecret." + applName, environment.getProperty("mosip.iam.adapter.clientsecret", ""));
		this.appID = environment.getProperty("mosip.iam.adapter.appid." + applName, environment.getProperty("mosip.iam.adapter.appid", ""));
	}

	@PostConstruct
	private void init() {
		if(isRenewalEnable) {
			ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
			taskScheduler.setPoolSize(1);
			taskScheduler.initialize();
			taskScheduler.scheduleAtFixedRate(new SelfTokenHandlerTask(), TimeUnit.MINUTES.toMillis(tokenExpiryCheckFrequency));
		}
	}

	private class SelfTokenHandlerTask implements Runnable {

		public void run() {
			if (cachedTokenObject.getToken() == null || !isTokenValid(cachedTokenObject.getToken())) {
				String authToken = tokenHelper.getClientToken(clientID, clientSecret, appID, webClient);
				cachedTokenObject.setToken(authToken);
			}
		}
	}

	private boolean isTokenValid(String authToken) {
		try {
			DecodedJWT decodedJWT = JWT.decode(authToken);
			Map<String, Claim> claims = decodedJWT.getClaims();
			LocalDateTime expiryTime = DateUtils.convertUTCToLocalDateTime(DateUtils.getUTCTimeFromDate(decodedJWT.getExpiresAt()));

			// time is added here so that expiry will be checked after that time and if it
			// does it will renew token
			if (!DateUtils.before(DateUtils.getUTCCurrentDateTime().plusMinutes(renewalBeforeExpiryInterval), expiryTime)) {
				return false;
			} else if (!claims.get("clientId").asString().equals(clientID)) {
				return false;
			} else {
				return true;
			}
		} catch (JWTDecodeException e) {
			LOGGER.error("JWT DECODE EXCEPTION ::".concat(e.getMessage()).concat(ExceptionUtils.getStackTrace(e)));
		} catch (Exception e) {
			LOGGER.error(e.getMessage().concat(ExceptionUtils.getStackTrace(e)));
		}
		return false;
	}

}