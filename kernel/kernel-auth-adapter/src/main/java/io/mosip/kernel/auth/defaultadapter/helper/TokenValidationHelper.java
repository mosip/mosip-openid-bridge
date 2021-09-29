package io.mosip.kernel.auth.defaultadapter.helper;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.exception.AuthManagerException;
import io.mosip.kernel.core.authmanager.authadapter.model.MosipUserDto;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.DateUtils;

@Component
public class TokenValidationHelper {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidationHelper.class);

    @Value("${auth.server.admin.validate.url:}")
	private String adminValidateUrl;

    @Value("${auth.server.admin.offline.token.validate:true}")
	private boolean offlineTokenValidate;

    @Value("${spring.profiles.active:}")
	String activeProfile;

    @Value("${auth.server.admin.certs.path:/protocol/openid-connect/certs}")
    String certsPath;

    @Autowired
	private ObjectMapper objectMapper;

    private Map<String, PublicKey> publicKeys = new HashMap<>();

    public MosipUserDto getTokenValidatedUserResponse(String token, RestTemplate restTemplate) {

        if (!offlineTokenValidate) {
            return doOnlineTokenValidation(token, restTemplate);
        }
        return doOfflineTokenValidation(token, restTemplate);
    }

    public MosipUserDto getOnlineTokenValidatedUserResponse(String token, RestTemplate restTemplate) {
        return doOnlineTokenValidation(token, restTemplate);
    }

    private MosipUserDto doOnlineTokenValidation(String token, RestTemplate restTemplate) {
        if (adminValidateUrl == null || "".equals(adminValidateUrl)) {
            LOGGER.warn("Auth Service Validate URL is not available in config file, not requesting for auth token validation.");
            throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), 
                            AuthAdapterErrorCode.UNAUTHORIZED.getErrorMessage());
        }
		HttpHeaders headers = new HttpHeaders();
		headers.set(AuthAdapterConstant.AUTH_HEADER_COOKIE, AuthAdapterConstant.AUTH_HEADER + token);
		HttpEntity<String> entity = new HttpEntity<>("parameters", headers);
        
        ResponseEntity<String> response = null;
		try {			
			response = restTemplate.exchange(adminValidateUrl, HttpMethod.GET, entity, String.class);
		} catch (RestClientException e) {
			throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), e.getMessage(), e);
		}

        List<ServiceError> validationErrorsList = ExceptionUtils.getServiceErrorList(response.getBody());
        if (!validationErrorsList.isEmpty()) {
            throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), validationErrorsList);
        }

        try {
            ResponseWrapper<?> responseObject = objectMapper.readValue(response.getBody(), ResponseWrapper.class);
            MosipUserDto mosipUserDto = objectMapper.readValue(objectMapper.writeValueAsString(
                                        responseObject.getResponse()), MosipUserDto.class);
            LOGGER.info("user (online verificate) " + mosipUserDto.getUserId());
            return mosipUserDto;
        } catch (Exception e) {
            throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), e.getMessage(), e);
        }
	}

    private MosipUserDto doOfflineTokenValidation(String token, RestTemplate restTemplate) {

        if(activeProfile.equalsIgnoreCase("local")) {
            return doOfflineLocalTokenValidation(token);
        }
        return doOfflineEnvTokenValidation(token, restTemplate);
    }

    private MosipUserDto doOfflineLocalTokenValidation(String jwtToken) {
        LOGGER.info("offline verification for local profile.");
        DecodedJWT decodedJWT = JWT.require(Algorithm.none()).build().verify(jwtToken);
		return buildMosipUser(decodedJWT, jwtToken);
    }

    private MosipUserDto doOfflineEnvTokenValidation(String jwtToken, RestTemplate restTemplate) {

        DecodedJWT decodedJWT = JWT.decode(jwtToken);

        PublicKey publicKey = getPublicKey(decodedJWT);
        // Still not able to get the public key either from server or local cache,
        // proceed with online token validation.
        if (Objects.isNull(publicKey)) {
            return doOnlineTokenValidation(jwtToken, restTemplate);
        }

        String tokenAlgo = decodedJWT.getAlgorithm();
        String keyId = decodedJWT.getKeyId();
        LOGGER.info(String.format("Public Key Found for Key Id: %s", keyId));
        // Public Key available, proceed with offline validation.
        Algorithm algorithm = getVerificationAlgorithm(tokenAlgo, publicKey);
        try {
            algorithm.verify(decodedJWT);
            LocalDateTime expiryTime = DateUtils.convertUTCToLocalDateTime(DateUtils.getUTCTimeFromDate(decodedJWT.getExpiresAt()));
            if (!DateUtils.before(DateUtils.getUTCCurrentDateTime(), expiryTime)) {
                throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), AuthAdapterErrorCode.UNAUTHORIZED.getErrorMessage());
            }
        } catch(SignatureVerificationException signatureException) {
            throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), signatureException.getMessage(), signatureException);
        }
        
        return buildMosipUser(decodedJWT, jwtToken);
    }

    private PublicKey getPublicKey(DecodedJWT decodedJWT ) {
        LOGGER.info("offline verification for environment profile.");
        
        String keyId = decodedJWT.getKeyId();
        PublicKey publicKey = publicKeys.get(keyId);

        if (Objects.isNull(publicKey)) {
            String issuerURI = decodedJWT.getIssuer();
            publicKey = getIssuerPublicKey(issuerURI, keyId);
            publicKeys.put(keyId, publicKey);
        }
        return publicKey;
    }

    private PublicKey getIssuerPublicKey(String issuerURI, String keyId) {
        try {
            URI uri = new URI(issuerURI + certsPath).normalize();
            JwkProvider provider = new UrlJwkProvider(uri.toURL());
            Jwk jwk = provider.get(keyId);
            return jwk.getPublicKey();
        } catch (JwkException | URISyntaxException | MalformedURLException e) {
            LOGGER.error("Error downloading Public key from server".concat(e.getMessage()));
        }
        return null;        
    }

    private Algorithm getVerificationAlgorithm(String tokenAlgo, PublicKey publicKey){
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
    private MosipUserDto buildMosipUser(DecodedJWT decodedJWT, String jwtToken) {
        MosipUserDto mosipUserDto = new MosipUserDto();
        String user = decodedJWT.getSubject();
		mosipUserDto.setToken(jwtToken);
		mosipUserDto.setMail(decodedJWT.getClaim(AuthAdapterConstant.EMAIL).asString());
		mosipUserDto.setMobile(decodedJWT.getClaim(AuthAdapterConstant.MOBILE).asString());
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
		    mosipUserDto.setUserId(user);
        } else {
            String azp = decodedJWT.getClaim(AuthAdapterConstant.AZP).asString();
            mosipUserDto.setRole(decodedJWT.getClaim(AuthAdapterConstant.ROLES).asString());
            mosipUserDto.setName(user);
		    mosipUserDto.setUserId(azp);
        }
		
        LOGGER.info("user (offline verificate): " + mosipUserDto.getUserId());
		return mosipUserDto;
    }

    public MosipUserDto doOnlineTokenValidation(String token, WebClient webClient) {
		HttpHeaders headers = new HttpHeaders();
		headers.set(AuthAdapterConstant.AUTH_HEADER_COOKIE, AuthAdapterConstant.AUTH_HEADER + token);
				
        ClientResponse response = webClient.method(HttpMethod.GET)
                                           .uri(UriComponentsBuilder.fromUriString(adminValidateUrl).toUriString())
                                           .headers(httpHeaders -> {
                                                httpHeaders.addAll(headers);
                                            })
                                           .exchange()
                                           .block();
        if (response.statusCode() == HttpStatus.OK) {
            ObjectNode responseBody = response.bodyToMono(ObjectNode.class).block();
            List<ServiceError> validationErrorsList = ExceptionUtils.getServiceErrorList(responseBody.asText());
            if (!validationErrorsList.isEmpty()) {
                throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), validationErrorsList);
            }

            if (responseBody != null && responseBody.get("response").get("status").asText().equalsIgnoreCase("success")) {
                try {
                    MosipUserDto mosipUserDto = objectMapper.readValue(objectMapper.writeValueAsString(
                                            responseBody.asText()), MosipUserDto.class);
                    LOGGER.info("user (online verificate - WebClient) " + mosipUserDto.getUserId());
                    return mosipUserDto;
                } catch (Exception e) {
                    throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), e.getMessage(), e);
                }
            }
        }                
		LOGGER.error("user authentication failed for the provided token (WebClient).");
		throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), AuthAdapterErrorCode.UNAUTHORIZED.getErrorMessage());
		
	}
}   


