package io.mosip.kernel.auth.defaultadapter.helper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;

@Component
public class ValidateTokenHelper {

	private static final Logger LOGGER = LoggerFactory.getLogger(ValidateTokenHelper.class);

	private Map<String, PublicKey> publicKeys = new HashMap<>();

	@Value("${auth.server.admin.oidc.certs.path:/protocol/openid-connect/certs}")
	private String certsPath;

	@Value("${auth.server.admin.oidc.userinfo.path:/protocol/openid-connect/userinfo}")
	private String userInfo;

	@Value("${auth.server.admin.issuer.domain.validate:true}")
	private boolean validateIssuerDomain;

	/**
	 * This should be same as the value in the token	
	 */
	@Value("${auth.server.admin.issuer.uri:}")
	private String issuerURI;

	/**
	 * This property will directly apply the certs URL without need for constructing the path from issuer URL. 
	 * This is useful to keep a different certs URL for integrating with MOSIP IdP for token validation.
	 */
	@Value("${auth.server.admin.oidc.certs.url:}")
	private String certsUrl;
	
	/**
	 * This property will directly apply the userInfo URL without need for constructing the path from issuer URL. 
	 * This is useful to keep a different userInfo URL for integrating with MOSIP IdP for token validation.
	 */
	@Value("${auth.server.admin.oidc.userinfo.url:}")
	private String userInfoUrl;
	
	/**
	 * When we validate a token we use the issuerURL. In case you want us to
	 * validate using an internal URL then the same has to be configured here.
	 */
	@Value("${auth.server.admin.issuer.internal.uri:}")
	private String issuerInternalURI;
	@Value("${auth.server.admin.audience.claim.validate:true}")
	private boolean validateAudClaim;

	// @Value("${auth.server.admin.allowed.audience:}")
	private List<String> allowedAudience;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private Environment environment;

	@PostConstruct
	@SuppressWarnings("unchecked")
	private void init() {
		String applName = getApplicationName();
		this.allowedAudience = (List<String>) environment.getProperty("auth.server.admin.allowed.audience." + applName,
				List.class,
				environment.getProperty("auth.server.admin.allowed.audience", List.class, Collections.EMPTY_LIST));
		issuerInternalURI = issuerInternalURI.trim().isEmpty() ? issuerURI : issuerInternalURI;
	}

	private String getApplicationName() {
		String appNames = environment.getProperty("spring.application.name");
		if (!EmptyCheckUtils.isNullEmpty(appNames)) {
			List<String> appNamesList = Stream.of(appNames.split(",")).collect(Collectors.toList());
			return appNamesList.get(0);
		} else {
			throw new RuntimeException("property spring.application.name not found");
		}
	}

	public MosipUserDto doOfflineLocalTokenValidation(String jwtToken) {
		LOGGER.info("offline verification for local profile.");
		DecodedJWT decodedJWT = JWT.require(Algorithm.none()).build().verify(jwtToken);
		return buildMosipUser(decodedJWT, jwtToken);
	}

	public ImmutablePair<Boolean, AuthAdapterErrorCode> isTokenValid(DecodedJWT decodedJWT, PublicKey publicKey) {
		// First, token expire
		LocalDateTime expiryTime = DateUtils
				.convertUTCToLocalDateTime(DateUtils.getUTCTimeFromDate(decodedJWT.getExpiresAt()));
		String userName = decodedJWT.getClaim(AuthAdapterConstant.PREFERRED_USERNAME).asString();
		if (!DateUtils.before(DateUtils.getUTCCurrentDateTime(), expiryTime)) {
			LOGGER.error("Provided Auth Token expired. Throwing Authentication Exception. UserName: " + userName);
			return ImmutablePair.of(Boolean.FALSE, AuthAdapterErrorCode.UNAUTHORIZED);
		}

		// Second, issuer domain check.
		boolean tokenDomainMatch = getTokenIssuerDomain(decodedJWT);
		if (validateIssuerDomain && !tokenDomainMatch) {
			LOGGER.error(
					"Provided Auth Token Issue domain does not match. Throwing Authentication Exception. UserName: "
							+ userName);
			return ImmutablePair.of(Boolean.FALSE, AuthAdapterErrorCode.UNAUTHORIZED);
		}

		// Third, signature validation.
		try {
			String tokenAlgo = decodedJWT.getAlgorithm();
			Algorithm algorithm = getVerificationAlgorithm(tokenAlgo, publicKey);
			algorithm.verify(decodedJWT);
		} catch (SignatureVerificationException signatureException) {
			LOGGER.error("Signature validation failed, Throwing Authentication Exception. UserName: " + userName,
					signatureException);
			return ImmutablePair.of(Boolean.FALSE, AuthAdapterErrorCode.UNAUTHORIZED);
		}

		// Fourth, audience | azp validation.
		boolean matchFound = validateAudience(decodedJWT);
		// No match found after comparing audience & azp
		if (!matchFound) {
			LOGGER.error("Provided Client Id does not match with Aud/AZP. Throwing Authorizaion Exception. UserName: "
					+ userName);
			return ImmutablePair.of(Boolean.FALSE, AuthAdapterErrorCode.FORBIDDEN);
		}
		return ImmutablePair.of(Boolean.TRUE, null);
	}

	private boolean validateAudience(DecodedJWT decodedJWT) {
		boolean matchFound = false;
		if (validateAudClaim) {

			List<String> tokenAudience = decodedJWT.getAudience();
			matchFound = tokenAudience.stream().anyMatch(allowedAudience::contains);

			// comparing with azp.
			String azp = decodedJWT.getClaim(AuthAdapterConstant.AZP).asString();
			if (!matchFound) {
				matchFound = allowedAudience.stream().anyMatch(azp::equalsIgnoreCase);
			}
		}
		return matchFound;
	}

	/**
	 * This method validates if the issuer domain in the JWT matches the issuerURI
	 * configured in the properties.
	 * 
	 * @param decodedJWT
	 * @return
	 */
	private boolean getTokenIssuerDomain(DecodedJWT decodedJWT) {
		String domain = decodedJWT.getClaim(AuthAdapterConstant.ISSUER).asString();
		try {
			String tokenHost = new URI(domain).getHost();
			String issuerHost = new URI(issuerURI).getHost();
			return tokenHost.equalsIgnoreCase(issuerHost);
		} catch (URISyntaxException synExp) {
			LOGGER.error("Unable to parse domain from issuer.", synExp);
		}
		return false;
	}

	public PublicKey getPublicKey(DecodedJWT decodedJWT) {
		String userName = decodedJWT.getClaim(AuthAdapterConstant.PREFERRED_USERNAME).asString();
		LOGGER.info("offline verification for environment profile. UserName: " + userName);

		String keyId = decodedJWT.getKeyId();
		PublicKey publicKey = publicKeys.get(keyId);

		if (Objects.isNull(publicKey)) {
			if(certsUrl == null || certsUrl.isEmpty()) {
				String realm = getRealM(decodedJWT);
				publicKey = getIssuerPublicKey(keyId, certsPath, realm);
			} else {
				publicKey = getIssuerPublicKey(keyId, certsUrl);
			}
			publicKeys.put(keyId, publicKey);
		}
		return publicKey;
	}

	private String getRealM(DecodedJWT decodedJWT) {
		String tokenIssuer = decodedJWT.getClaim(AuthAdapterConstant.ISSUER).asString();
		return tokenIssuer.substring(tokenIssuer.lastIndexOf("/") + 1);
	}

	private PublicKey getIssuerPublicKey(String keyId, String certsPathVal, String realm) {
		return getIssuerPublicKey(keyId, issuerInternalURI + realm + certsPathVal);
	}
	
	private PublicKey getIssuerPublicKey(String keyId, String certsUrIPath) {
		try {

			URI uri = new URI(certsUrIPath).normalize();
			JwkProvider provider = new UrlJwkProvider(uri.toURL());
			Jwk jwk = provider.get(keyId);
			return jwk.getPublicKey();
		} catch (JwkException | URISyntaxException | MalformedURLException e) {
			LOGGER.error("Error downloading Public key from server".concat(e.getMessage()));
		}
		return null;
	}

	private Algorithm getVerificationAlgorithm(String tokenAlgo, PublicKey publicKey) {
		// Later will add other Algorithms.
		switch (tokenAlgo) {
		case "RS256":
			return Algorithm.RSA256((RSAPublicKey) publicKey, null);
		case "RS384":
			return Algorithm.RSA384((RSAPublicKey) publicKey, null);
		case "RS512":
			return Algorithm.RSA512((RSAPublicKey) publicKey, null);
		default:
			return Algorithm.RSA256((RSAPublicKey) publicKey, null);
		}
	}

	@SuppressWarnings("unchecked")
	public MosipUserDto buildMosipUser(DecodedJWT decodedJWT, String jwtToken) {
		MosipUserDto mosipUserDto = new MosipUserDto();
		String user = decodedJWT.getSubject();
		mosipUserDto.setToken(jwtToken);
		mosipUserDto.setMail(decodedJWT.getClaim(AuthAdapterConstant.EMAIL).asString());
		mosipUserDto.setMobile(decodedJWT.getClaim(AuthAdapterConstant.MOBILE).asString());
		mosipUserDto.setUserId(decodedJWT.getClaim(AuthAdapterConstant.PREFERRED_USERNAME).asString());
		Claim realmAccess = decodedJWT.getClaim(AuthAdapterConstant.REALM_ACCESS);
		if (!realmAccess.isNull()) {
			List<String> roles = (List<String>) realmAccess.asMap().get("roles");
			StringBuilder strBuilder = new StringBuilder();

			for (String role : roles) {
				strBuilder.append(role);
				strBuilder.append(AuthAdapterConstant.COMMA);
			}
			mosipUserDto.setRole(strBuilder.toString());
			mosipUserDto.setName(user);
		} else {
			mosipUserDto.setRole(decodedJWT.getClaim(AuthAdapterConstant.ROLES).asString());
			mosipUserDto.setName(user);
		}

		LOGGER.info("user (offline verification done): " + mosipUserDto.getUserId());
		return mosipUserDto;
	}

	public ImmutablePair<HttpStatus, MosipUserDto> doOnlineTokenValidation(String jwtToken, RestTemplate restTemplate) {
		if ("".equals(issuerURI) || "".equals(issuerInternalURI)) {
			LOGGER.warn("OIDC validate URL is not available in config file, not requesting for token validation.");
			return ImmutablePair.of(HttpStatus.EXPECTATION_FAILED, null);
		}

		DecodedJWT decodedJWT = JWT.decode(jwtToken);
		HttpHeaders headers = new HttpHeaders();
		headers.add(AuthAdapterConstant.AUTH_REQUEST_COOOKIE_HEADER, AuthAdapterConstant.BEARER_STR + jwtToken);
		HttpEntity<String> entity = new HttpEntity<>("parameters", headers);
		ResponseEntity<String> response = null;
		HttpStatusCodeException statusCodeException = null;
		try {
			String userInfoPath = getUserInfoPath(decodedJWT);
			response = restTemplate.exchange(userInfoPath, HttpMethod.GET, entity, String.class);
		} catch (HttpClientErrorException | HttpServerErrorException e) {
			LOGGER.error("Token validation failed for accessToken {}", jwtToken, e);
			statusCodeException = e;
		}

		if (Objects.nonNull(statusCodeException)) {
			JsonNode errorNode;
			try {
				errorNode = objectMapper.readTree(statusCodeException.getResponseBodyAsString());
				LOGGER.error("Token validation failed error {} and message {}",
						errorNode.get(AuthAdapterConstant.ERROR), errorNode.get(AuthAdapterConstant.ERROR_DESC));
				return ImmutablePair.of(statusCodeException.getStatusCode(), null);
			} catch (IOException e) {
				LOGGER.error("IO Excepton in parsing response {}", e.getMessage());
			}
		}

		if (response != null && response.getStatusCode().is2xxSuccessful()) {
			// validating audience | azp claims.
			boolean matchFound = validateAudience(decodedJWT);
			if (!matchFound) {
				LOGGER.error("Provided Client Id does not match with Aud/AZP. Throwing Authorizaion Exception");
				return ImmutablePair.of(HttpStatus.FORBIDDEN, null);
			}
			MosipUserDto mosipUserDto = buildMosipUser(decodedJWT, jwtToken);
			return ImmutablePair.of(HttpStatus.OK, mosipUserDto);
		}
		return ImmutablePair.of(HttpStatus.UNAUTHORIZED, null);
	}

	private String getUserInfoPath(DecodedJWT decodedJWT) {
		String userInfoPath;
		if(userInfoUrl == null || userInfoUrl.isEmpty()) {
			String realm = getRealM(decodedJWT);
			userInfoPath = issuerInternalURI + realm + userInfo;
		} else {
			userInfoPath = userInfoUrl;
		}
		return userInfoPath;
	}

	public ImmutablePair<HttpStatus, MosipUserDto> doOnlineTokenValidation(String jwtToken, WebClient webClient) {
		if ("".equals(issuerURI) || "".equals(issuerInternalURI)) {
			LOGGER.warn("OIDC validate URL is not available in config file, not requesting for token validation.");
			return ImmutablePair.of(HttpStatus.EXPECTATION_FAILED, null);
		}

		DecodedJWT decodedJWT = JWT.decode(jwtToken);
		HttpHeaders headers = new HttpHeaders();
		headers.add(AuthAdapterConstant.AUTH_REQUEST_COOOKIE_HEADER, AuthAdapterConstant.BEARER_STR + jwtToken);
		String userInfoPath = getUserInfoPath(decodedJWT);
		ClientResponse response = webClient.method(HttpMethod.GET).uri(userInfoPath).headers(httpHeaders -> {
			httpHeaders.addAll(headers);
		}).exchange().block();
		if (response != null && response.statusCode() == HttpStatus.OK) {
			ObjectNode responseBody = response.bodyToMono(ObjectNode.class).block();
			if (responseBody != null) {
				List<ServiceError> validationErrorsList = ExceptionUtils.getServiceErrorList(responseBody.asText());
				if (!validationErrorsList.isEmpty()) {
					LOGGER.error("Error in validate token. Code {}, message {}",
							validationErrorsList.get(0).getErrorCode(), validationErrorsList.get(0).getMessage());
					return ImmutablePair.of(HttpStatus.UNAUTHORIZED, null);
				}
			}

			// validating audience | azp claims.
			boolean matchFound = validateAudience(decodedJWT);
			if (!matchFound) {
				LOGGER.error("Provided Client Id does not match with Aud/AZP. Throwing Authorizaion Exception");
				return ImmutablePair.of(HttpStatus.FORBIDDEN, null);
			}
			MosipUserDto mosipUserDto = buildMosipUser(decodedJWT, jwtToken);
			return ImmutablePair.of(HttpStatus.OK, mosipUserDto);
		}
		LOGGER.error("user authentication failed for the provided token (WebClient).");
		return ImmutablePair.of(HttpStatus.UNAUTHORIZED, null);
	}

}
