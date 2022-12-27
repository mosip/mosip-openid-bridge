package io.mosip.kernel.auth.defaultadapter.helper;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

@Lazy
@Component
public class VertxTokenValidationHelper {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(VertxTokenValidationHelper.class);

    @Value("${auth.server.admin.validate.url:}")
	private String adminValidateUrl;

    @Value("${auth.server.admin.offline.vertx.token.validate:true}")
	private boolean offlineTokenValidate;

    @Value("${spring.profiles.active:}")
	String activeProfile;

    @Autowired
	private ObjectMapper objectMapper;

    @Autowired
    private ValidateTokenHelper validateTokenHelper;

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
        ImmutablePair<HttpStatus, MosipUserDto> validateResp = validateTokenHelper.doOnlineTokenValidation(token, restTemplate);
        if (validateResp.getLeft() == HttpStatus.EXPECTATION_FAILED) {
            sendErrors(routingContext, AuthAdapterErrorCode.CONNECT_EXCEPTION, AuthAdapterConstant.INTERNEL_SERVER_ERROR);
        }
        
        if (validateResp.getLeft() == HttpStatus.UNAUTHORIZED) { 
            sendErrors(routingContext, AuthAdapterErrorCode.UNAUTHORIZED, AuthAdapterConstant.NOTAUTHENTICATED);
        }

        if (validateResp.getLeft() == HttpStatus.FORBIDDEN) {
            sendErrors(routingContext, AuthAdapterErrorCode.FORBIDDEN, AuthAdapterConstant.UNAUTHORIZED); 
        }

        if (validateResp.getLeft() != HttpStatus.OK) { 
            sendErrors(routingContext, AuthAdapterErrorCode.UNAUTHORIZED, AuthAdapterConstant.NOTAUTHENTICATED);
        }

        return validateResp.getRight();
    }

    private MosipUserDto doOfflineTokenValidation(String token, RestTemplate restTemplate, 
                RoutingContext routingContext) throws JsonParseException, JsonMappingException, 
                IOException {

        if(activeProfile.equalsIgnoreCase("local")) {
            return validateTokenHelper.doOfflineLocalTokenValidation(token);
        }
        return doOfflineEnvTokenValidation(token, restTemplate, routingContext);
    }

    private MosipUserDto doOfflineEnvTokenValidation(String jwtToken, RestTemplate restTemplate, 
                        RoutingContext routingContext) throws JsonParseException, JsonMappingException, 
                        IOException {

        DecodedJWT decodedJWT = JWT.decode(jwtToken);

        PublicKey publicKey = validateTokenHelper.getPublicKey(decodedJWT);
        // Still not able to get the public key either from server or local cache,
        // proceed with online token validation.
        if (Objects.isNull(publicKey)) {
            return doOnlineTokenValidation(jwtToken, restTemplate, routingContext);
        }

        ImmutablePair<Boolean, AuthAdapterErrorCode> validateResp = validateTokenHelper.isTokenValid(decodedJWT, publicKey);
        if (validateResp.getLeft() == Boolean.FALSE) {
            int httpStatusCode = validateResp.getRight() == AuthAdapterErrorCode.UNAUTHORIZED ? 
                                    AuthAdapterConstant.NOTAUTHENTICATED : AuthAdapterConstant.UNAUTHORIZED;
            sendErrors(routingContext, validateResp.getRight(), httpStatusCode);
            return null;
        }
        return validateTokenHelper.buildMosipUser(decodedJWT, jwtToken);
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
}   


