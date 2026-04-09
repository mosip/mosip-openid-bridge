package io.mosip.kernel.auth.defaultadapter.config;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.web.reactive.function.client.WebClient;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.model.TokenHolder;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.util.DateUtils2;
import jakarta.annotation.PostConstruct;

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

	private ThreadPoolTaskScheduler taskScheduler;

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
		if (!isRenewalEnable) {
			LOGGER.info("Self token background renewal is disabled");
			return;
		}

		if (clientID.isEmpty() || clientSecret.isEmpty()) {
			LOGGER.warn("ClientID or ClientSecret not configured. Self token renewal disabled.");
			return;
		}
		taskScheduler = new ThreadPoolTaskScheduler();
		taskScheduler.setPoolSize(1);
		taskScheduler.setThreadNamePrefix("SelfToken-Renewal-");
		taskScheduler.setDaemon(true);
		taskScheduler.initialize();

		// Schedule task to run every N minutes
		taskScheduler.scheduleAtFixedRate(
				new SelfTokenRenewalTask(),
				TimeUnit.MINUTES.toMillis(tokenExpiryCheckFrequency)
		);

		LOGGER.info("SelfTokenRenewalTaskExecutor started. Check frequency: {} minutes, Renew before expiry: {} minutes",
				tokenExpiryCheckFrequency, renewalBeforeExpiryInterval);
	}

	@PreDestroy
	public void shutdown() {
		if (taskScheduler != null) {
			LOGGER.info("Shutting down SelfTokenRenewalTaskExecutor");
			taskScheduler.shutdown();
		}
	}

	private class SelfTokenRenewalTask implements Runnable {
		@Override
		public void run() {
			String currentToken = cachedTokenObject.getToken();
			if (currentToken == null || !isTokenValid(currentToken)) {
				String newToken = tokenHelper.getClientToken(clientID, clientSecret, appID, webClient);
				if (newToken != null && !newToken.isEmpty()) {
					cachedTokenObject.setToken(newToken);
					LOGGER.info("Self token successfully renewed in background");
				} else {
					LOGGER.error("Failed to get new self token from IAM");
				}
			}
		}
	}

	private boolean isTokenValid(String authToken) {
		try {
			DecodedJWT decodedJWT = JWT.decode(authToken);
			Map<String, Claim> claims = decodedJWT.getClaims();

			if (!clientID.equals(claims.get("clientId").asString())) {
				return false;
			}

			LocalDateTime expiryTime = DateUtils2.convertUTCToLocalDateTime(
					DateUtils2.getUTCTimeFromDate(decodedJWT.getExpiresAt()));

			// Renew if token will expire within renewalBeforeExpiryMinutes
			LocalDateTime renewalThreshold = DateUtils2.getUTCCurrentDateTime()
					.plusMinutes(renewalBeforeExpiryInterval);
			return DateUtils2.before(renewalThreshold, expiryTime);
		} catch (JWTDecodeException e) {
			LOGGER.error("JWT DECODE EXCEPTION ::".concat(e.getMessage()).concat(ExceptionUtils.getStackTrace(e)));
		} catch (Exception e) {
			LOGGER.error(e.getMessage().concat(ExceptionUtils.getStackTrace(e)));
		}
		return false;
	}
}
