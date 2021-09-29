package io.mosip.kernel.auth.defaultadapter.helper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.ArrayList;
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
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.core.authmanager.authadapter.model.MosipUserDto;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.DateUtils;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

@Lazy
@Component
public class VertxTokenValidationHelper {
    
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

    public MosipUserDto getTokenValidatedVertxUserResponse(RestTemplate restTemplate, RoutingContext routingContext, 
                String[] roles) throws JsonParseException, JsonMappingException, IOException {

		HttpServerRequest httpRequest = routingContext.request();
		String token = null;
		String cookies = httpRequest.getHeader(AuthAdapterConstant.AUTH_HEADER_COOKIE);
		if (cookies != null && !cookies.isEmpty() && cookies.contains(AuthAdapterConstant.AUTH_HEADER)) {
			token = cookies.replace(AuthAdapterConstant.AUTH_HEADER, "").trim();
		}
		if (token == null || token.isEmpty()) {
			sendErrors(routingContext, AuthAdapterErrorCode.UNAUTHORIZED, AuthAdapterConstant.NOTAUTHENTICATED);
			return null;
		}

		token = token.split(";")[0];
        MosipUserDto mosipUserDto = null;
        if (!offlineTokenValidate) {
            mosipUserDto = doOnlineTokenValidation(token, restTemplate, routingContext);
        } else {
            mosipUserDto = doOfflineTokenValidation(token, restTemplate, routingContext);
        }

        if (Objects.isNull(mosipUserDto)) {
            return null;    
        }

        boolean isAuthorized = false;
		String[] authorities = mosipUserDto.getRole().split(",");
		for (String role : roles) {
			for (String authority : authorities) {
				if (role.equals(authority)) {
					isAuthorized = true;
					break;
				}
			}
		}
		if (!isAuthorized) {
			sendErrors(routingContext, AuthAdapterErrorCode.FORBIDDEN, AuthAdapterConstant.UNAUTHORIZED);
			return null;
		}
        return mosipUserDto;
    }

    private MosipUserDto doOnlineTokenValidation(String token, RestTemplate restTemplate, 
                    RoutingContext routingContext) throws JsonParseException, JsonMappingException, 
                    IOException {
        if (adminValidateUrl == null || "".equals(adminValidateUrl)) {
            sendErrors(routingContext, AuthAdapterErrorCode.CONNECT_EXCEPTION, AuthAdapterConstant.INTERNEL_SERVER_ERROR);
        }
        HttpHeaders headers = new HttpHeaders();
		headers.set(AuthAdapterConstant.AUTH_HEADER_COOKIE, AuthAdapterConstant.AUTH_HEADER + token);
		HttpEntity<String> entity = new HttpEntity<>("parameters", headers);
        
        ResponseEntity<String> response = null;
		try {			
			response = restTemplate.exchange(adminValidateUrl, HttpMethod.GET, entity, String.class);
		} catch (RestClientException e) {
			sendErrors(routingContext, AuthAdapterErrorCode.CONNECT_EXCEPTION, AuthAdapterConstant.INTERNEL_SERVER_ERROR);
		}

        List<ServiceError> validationErrorsList = ExceptionUtils.getServiceErrorList(response.getBody());
        if (!validationErrorsList.isEmpty()) {
            LOGGER.error("count " + validationErrorsList.size());
			sendErrors(routingContext, validationErrorsList, AuthAdapterConstant.NOTAUTHENTICATED);
            return null;
        }
        ResponseWrapper<?> responseObject = objectMapper.readValue(response.getBody(), ResponseWrapper.class);
		MosipUserDto mosipUserDto = objectMapper.readValue(objectMapper.writeValueAsString(responseObject.getResponse()),
				MosipUserDto.class);

        return mosipUserDto;
    }

    private MosipUserDto doOfflineTokenValidation(String token, RestTemplate restTemplate, 
                RoutingContext routingContext) throws JsonParseException, JsonMappingException, 
                IOException {

        if(!activeProfile.equalsIgnoreCase("local")) {
            return doOfflineLocalTokenValidation(token);
        }
        return doOfflineEnvTokenValidation(token, restTemplate, routingContext);
    }

    private MosipUserDto doOfflineEnvTokenValidation(String jwtToken, RestTemplate restTemplate, 
                        RoutingContext routingContext) throws JsonParseException, JsonMappingException, 
                        IOException {

        DecodedJWT decodedJWT = JWT.decode(jwtToken);

        PublicKey publicKey = getPublicKey(decodedJWT);
        // Still not able to get the public key either from server or local cache,
        // proceed with online token validation.
        if (Objects.isNull(publicKey)) {
            return doOnlineTokenValidation(jwtToken, restTemplate, routingContext);
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
                sendErrors(routingContext, AuthAdapterErrorCode.UNAUTHORIZED, AuthAdapterConstant.UNAUTHORIZED);
            }
            return buildMosipUser(decodedJWT, jwtToken);
        } catch(SignatureVerificationException signatureException) {
            sendErrors(routingContext, AuthAdapterErrorCode.UNAUTHORIZED, AuthAdapterConstant.UNAUTHORIZED);
        }
        return null;
    }

    private void sendErrors(RoutingContext routingContext, AuthAdapterErrorCode errorCode, int statusCode) {
        
        List<ServiceError> errors = new ArrayList<>();
        ServiceError error = new ServiceError(errorCode.getErrorCode(), errorCode.getErrorMessage());
        LOGGER.error(error.getMessage());
        errors.add(error);
		sendErrors(routingContext, errors, statusCode);
	}

    private void sendErrors(RoutingContext routingContext, List<ServiceError> errors, int statusCode) {

		ResponseWrapper<ServiceError> errorResponse = new ResponseWrapper<>();
		errorResponse.getErrors().addAll(errors);
		objectMapper.registerModule(new JavaTimeModule());
		JsonNode reqNode;
		if (routingContext.getBodyAsJson() != null) {
			try {
				reqNode = objectMapper.readTree(routingContext.getBodyAsJson().toString());
				errorResponse.setId(reqNode.path("id").asText());
				errorResponse.setVersion(reqNode.path("version").asText());
			} catch (IOException exception) {
				LOGGER.error(exception.getMessage());
			}
		}
		try {
			routingContext.response().putHeader("content-type", "application/json").setStatusCode(statusCode)
					.end(objectMapper.writeValueAsString(errorResponse));

		} catch (JsonProcessingException exception) {
			LOGGER.error(exception.getMessage());
		}
	}

    private MosipUserDto doOfflineLocalTokenValidation(String jwtToken) {
        LOGGER.info("offline verification for local profile.");
        DecodedJWT decodedJWT = JWT.require(Algorithm.none()).build().verify(jwtToken);
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
}   


