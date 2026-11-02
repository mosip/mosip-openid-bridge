package io.mosip.kernel.authcodeflowproxy.api.validator;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.annotation.PostConstruct;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import io.mosip.kernel.core.util.DateUtils2;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.openid.bridge.api.constants.AuthConstant;
import io.mosip.kernel.openid.bridge.api.constants.AuthErrorCode;
import io.mosip.kernel.openid.bridge.api.constants.Errors;
import io.mosip.kernel.openid.bridge.api.exception.ServiceException;

/**
 * Token validator
 * 
 * @author Loganathan S
 *
 */
@Component
public class ValidateTokenUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(ValidateTokenUtil.class);

	private Map<String, PublicKey> publicKeys = new HashMap<>();

	private static final String ED25519_ALGORITHM = "Ed25519";
	private static final String EDDSA_ALGORITHM = "EdDSA";
	private static final String ES256K_ALGORITHM = "ES256K";
	private static final int JWKS_TIMEOUT_MS = 5000;
	private static final int JWKS_SIZE_LIMIT = 51200;

	@Value("${auth.server.admin.hmac.secret:}")
	private String hmacSecret;

	private Map<String, JWK> publicJWKs = new ConcurrentHashMap<>();

	@Value("${mosip.iam.certs_endpoint:}")
	private String certsPathUrl;

	@Value("${auth.server.admin.issuer.domain.validate:true}")
	private boolean validateIssuerDomain;

	@Value("${auth.server.admin.audience.claim.validate:true}")
	private boolean validateAudClaim;

	// @Value("${auth.server.admin.allowed.audience:}")
	private List<String> allowedAudience;

	@Autowired
	private Environment environment;

	@PostConstruct
	@SuppressWarnings("unchecked")
	private void init() {
		String applName = getApplicationName();
		this.allowedAudience = (List<String>) environment.getProperty("auth.server.admin.allowed.audience." + applName,
				List.class,
				environment.getProperty("auth.server.admin.allowed.audience", List.class, Collections.EMPTY_LIST));
	}

	private String getApplicationName() {
		String appNames = environment.getProperty("spring.application.name");
		if (appNames != null && !appNames.isEmpty()) {
			List<String> appNamesList = Stream.of(appNames.split(",")).collect(Collectors.toList());
			return appNamesList.get(0);
		} else {
			throw new RuntimeException("property spring.application.name not found");
		}
	}
	
	public void validateToken(String accessToken) {
		if(!isTokenValid(accessToken).getKey()){
			throw new ServiceException(Errors.INVALID_TOKEN.getErrorCode(), Errors.INVALID_TOKEN.getErrorMessage());
		}
	}
	
	public ImmutablePair<Boolean, AuthErrorCode> isTokenValid(String jwtToken) {
		return isTokenValid(JWT.decode(jwtToken));
	}

	public ImmutablePair<Boolean, AuthErrorCode> isTokenValid(DecodedJWT decodedJWT) {
		PublicKey publicKey = getPublicKey(decodedJWT);
		// First, token expire
		LocalDateTime expiryTime = DateUtils2
				.convertUTCToLocalDateTime(DateUtils2.getUTCTimeFromDate(decodedJWT.getExpiresAt()));
		String userName = decodedJWT.getClaim(AuthConstant.PREFERRED_USERNAME).asString();
		if (!DateUtils2.before(DateUtils2.getUTCCurrentDateTime(), expiryTime)) {
			LOGGER.error("Provided Auth Token expired. Throwing Authentication Exception. UserName: " + userName);
			return ImmutablePair.of(Boolean.FALSE, AuthErrorCode.UNAUTHORIZED);
		}

		// Second, issuer domain check.
		if (validateIssuerDomain && !getTokenIssuerDomain(decodedJWT)) {
			LOGGER.error(
					"Provided Auth Token Issue domain does not match. Throwing Authentication Exception. UserName: "
							+ userName);
			return ImmutablePair.of(Boolean.FALSE, AuthErrorCode.UNAUTHORIZED);
		}

		// Third, signature validation.
		ImmutablePair<Boolean, AuthErrorCode> signatureVerificationResult = verifyJWTSignagure(decodedJWT);
		// If signature validation fails return the error code
		if(!signatureVerificationResult.getLeft()) {
			return signatureVerificationResult;
		}
		
		// Fourth, audience | azp validation.
		// No match found after comparing audience & azp
		if (validateAudClaim && !validateAudience(decodedJWT)) {
			LOGGER.error("Provided Client Id does not match with Aud/AZP. Throwing Authorizaion Exception. UserName: "
					+ userName);
			return ImmutablePair.of(Boolean.FALSE, AuthErrorCode.FORBIDDEN);
		}
		return ImmutablePair.of(Boolean.TRUE, null);
	}

	private boolean validateAudience(DecodedJWT decodedJWT) {
		boolean matchFound;

		List<String> tokenAudience =  decodedJWT.getAudience();
		matchFound = tokenAudience != null && tokenAudience.stream().anyMatch(allowedAudience::contains);

		// comparing with azp.
		if (!matchFound) {
			Claim azp = decodedJWT.getClaim(AuthConstant.AZP);
			matchFound = azp != null && !azp.isMissing() && !azp.isNull() && allowedAudience.stream().anyMatch(azp.asString()::equalsIgnoreCase);
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
		String domain = decodedJWT.getClaim(AuthConstant.ISSUER).asString();
		try {
			String tokenHost = new URI(domain).getHost();
			return tokenHost.equalsIgnoreCase(new URI(certsPathUrl).getHost());
		} catch (URISyntaxException synExp) {
			LOGGER.error("Unable to parse domain from issuer.", synExp);
		}
		return false;
	}

	public PublicKey getPublicKey(DecodedJWT decodedJWT) {
		String userName = decodedJWT.getClaim(AuthConstant.PREFERRED_USERNAME).asString();
		LOGGER.info("offline verification for environment profile. UserName: " + userName);

		String keyId = decodedJWT.getKeyId();
		PublicKey publicKey = publicKeys.get(keyId);

		if (Objects.isNull(publicKey)) {
			publicKey = getIssuerPublicKey(keyId);
			publicKeys.put(keyId, publicKey);
		}
		return publicKey;
	}
	
	/**
	 * Verify the signature of the given JWT.
	 * 
	 * @param decodedJWT - the decoded JWT
	 * @return if it is valid or not and any error code in case if it not valid.
	 */
	public ImmutablePair<Boolean, AuthErrorCode> verifyJWTSignagure(DecodedJWT decodedJWT) {
		try {
			boolean signatureValid = true;
			String tokenAlgo = decodedJWT.getAlgorithm();
			if (isEd25519(tokenAlgo) || ES256K_ALGORITHM.equals(tokenAlgo)) {
				signatureValid = isNimbusSignatureValid(decodedJWT);
			} else {
				PublicKey publicKey = getPublicKey(decodedJWT);
				Algorithm algorithm = getVerificationAlgorithm(tokenAlgo, publicKey);
				algorithm.verify(decodedJWT);
			}
			if (!signatureValid) {
				LOGGER.error("Signature validation failed for User Info, Throwing Authentication Exception.");
				return ImmutablePair.of(Boolean.FALSE, AuthErrorCode.UNAUTHORIZED);
			}
		} catch (SignatureVerificationException | AlgorithmMismatchException signatureException) {
			LOGGER.error("Signature validation failed for User Info, Throwing Authentication Exception.",
					signatureException);
			return ImmutablePair.of(Boolean.FALSE, AuthErrorCode.UNAUTHORIZED);
		}

		return ImmutablePair.of(Boolean.TRUE, null);

	}

	// "Ed25519" is the current name; "EdDSA" is the older name still sent by some servers.
	private static boolean isEd25519(String tokenAlgo) {
		return ED25519_ALGORITHM.equals(tokenAlgo) || EDDSA_ALGORITHM.equals(tokenAlgo);
	}

	private boolean isNimbusSignatureValid(DecodedJWT decodedJWT) {
		String tokenAlgo = decodedJWT.getAlgorithm();
		try {
			JWK jwk = getPublicJWK(decodedJWT);
			JWSVerifier verifier;
			JWSAlgorithm algorithm;
			if (isEd25519(tokenAlgo) && jwk instanceof OctetKeyPair octetKeyPair) {
				verifier = new Ed25519Verifier(octetKeyPair);
				algorithm = JWSAlgorithm.EdDSA; // the name nimbus knows its Ed25519 verifier by
			} else if (ES256K_ALGORITHM.equals(tokenAlgo) && jwk instanceof ECKey ecKey) {
				ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(ecKey);
				ecdsaVerifier.getJCAContext().setProvider(BouncyCastleHolder.PROVIDER); // the JDK has no secp256k1 curve
				verifier = ecdsaVerifier;
				algorithm = JWSAlgorithm.ES256K;
			} else {
				return false;
			}
			byte[] signingInput = (decodedJWT.getHeader() + "." + decodedJWT.getPayload())
					.getBytes(StandardCharsets.US_ASCII);
			return verifier.verify(new JWSHeader(algorithm), signingInput, new Base64URL(decodedJWT.getSignature()));
		} catch (JOSEException | IOException | ParseException | URISyntaxException e) {
			LOGGER.error("Signature check of a " + tokenAlgo + " token failed", e);
			return false;
		}
	}

	private JWK getPublicJWK(DecodedJWT decodedJWT) throws IOException, ParseException, URISyntaxException {
		String certsUrIPath = certsPathUrl;
		String cacheKey = certsUrIPath + "#" + decodedJWT.getKeyId();
		JWK publicJWK = publicJWKs.get(cacheKey);
		if (publicJWK == null) {
			JWK jwk = JWKSet.load(new URI(certsUrIPath).normalize().toURL(), JWKS_TIMEOUT_MS, JWKS_TIMEOUT_MS,
					JWKS_SIZE_LIMIT).getKeyByKeyId(decodedJWT.getKeyId());
			if (jwk != null) {
				publicJWK = jwk.toPublicJWK();
				publicJWKs.put(cacheKey, publicJWK);
			}
		}
		return publicJWK;
	}

	private static final class BouncyCastleHolder {
		private static final Provider PROVIDER = new BouncyCastleProvider();
	}

	private PublicKey getIssuerPublicKey(String keyId) {
		try {

			URI uri = new URI(certsPathUrl).normalize();
			JwkProvider provider = new UrlJwkProvider(uri.toURL());
			Jwk jwk = provider.get(keyId);
			return jwk.getPublicKey();
		} catch (JwkException | URISyntaxException | MalformedURLException e) {
			LOGGER.error("Error downloading Public key from server".concat(e.getMessage()));
		}
		return null;
	}

	private Algorithm getVerificationAlgorithm(String tokenAlgo, PublicKey publicKey) {
		switch (tokenAlgo) {
		case "RS256":
			return Algorithm.RSA256((RSAPublicKey) publicKey, null);
		case "RS384":
			return Algorithm.RSA384((RSAPublicKey) publicKey, null);
		case "RS512":
			return Algorithm.RSA512((RSAPublicKey) publicKey, null);
		case "PS256":
			return Algorithm.RSA256PSS((RSAPublicKey) publicKey, null);
		case "PS384":
			return Algorithm.RSA384PSS((RSAPublicKey) publicKey, null);
		case "PS512":
			return Algorithm.RSA512PSS((RSAPublicKey) publicKey, null);
		case "ES256":
			return Algorithm.ECDSA256((ECPublicKey) publicKey, null);
		case "ES384":
			return Algorithm.ECDSA384((ECPublicKey) publicKey, null);
		case "ES512":
			return Algorithm.ECDSA512((ECPublicKey) publicKey, null);
		case "HS384":
			return Algorithm.HMAC384(hmacKey(48));
		case "HS512":
			return Algorithm.HMAC512(hmacKey(64));
		default:
			return Algorithm.RSA256((RSAPublicKey) publicKey, null);
		}
	}

	private byte[] hmacKey(int minLength) {
		byte[] key = hmacSecret.getBytes(StandardCharsets.UTF_8);
		if (key.length < minLength) {
			throw new AlgorithmMismatchException("The HMAC secret is not set or is shorter than " + minLength + " bytes");
		}
		return key;
	}
}
