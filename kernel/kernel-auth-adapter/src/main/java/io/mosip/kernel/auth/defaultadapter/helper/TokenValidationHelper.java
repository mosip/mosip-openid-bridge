package io.mosip.kernel.auth.defaultadapter.helper;

import java.security.PublicKey;
import java.util.Objects;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.exception.AuthManagerException;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;

@Component
public class TokenValidationHelper {
    
    @Value("${auth.server.admin.offline.comp.token.validate:true}")
	private boolean offlineTokenValidate;

    @Value("${spring.profiles.active:}")
	String activeProfile;

    @Value("${auth.server.admin.certs.path:/protocol/openid-connect/certs}")
    String certsPath;

    @Autowired
    private ValidateTokenHelper validateTokenHelper;

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
        ImmutablePair<HttpStatus, MosipUserDto> validateResp = validateTokenHelper.doOnlineTokenValidation(token, restTemplate);

        if (validateResp.getLeft() == HttpStatus.EXPECTATION_FAILED || validateResp.getLeft() == HttpStatus.UNAUTHORIZED) {
            throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), 
                            AuthAdapterErrorCode.UNAUTHORIZED.getErrorMessage());
        }
        if (validateResp.getLeft() == HttpStatus.FORBIDDEN) { 
            throw new AuthManagerException(AuthAdapterErrorCode.FORBIDDEN.getErrorCode(), 
                            AuthAdapterErrorCode.FORBIDDEN.getErrorMessage());
        }
        if (validateResp.getLeft() != HttpStatus.OK) { 
            throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), 
                            AuthAdapterErrorCode.UNAUTHORIZED.getErrorMessage());
        }

		return validateResp.getRight();
	}

    private MosipUserDto doOfflineTokenValidation(String token, RestTemplate restTemplate) {

        if(activeProfile.equalsIgnoreCase("local")) {
            return validateTokenHelper.doOfflineLocalTokenValidation(token);
        }
        return doOfflineEnvTokenValidation(token, restTemplate);
    }

    private MosipUserDto doOfflineEnvTokenValidation(String jwtToken, RestTemplate restTemplate) {

        DecodedJWT decodedJWT = JWT.decode(jwtToken);

        PublicKey publicKey = validateTokenHelper.getPublicKey(decodedJWT);
        // Still not able to get the public key either from server or local cache,
        // proceed with online token validation.
        if (Objects.isNull(publicKey)) {
            return doOnlineTokenValidation(jwtToken, restTemplate);
        }

        ImmutablePair<Boolean, AuthAdapterErrorCode> validateResp = validateTokenHelper.isTokenValid(decodedJWT, publicKey);
        if (validateResp.getLeft() == Boolean.FALSE) { 
            throw new AuthManagerException(validateResp.getRight().getErrorCode(), validateResp.getRight().getErrorMessage());
        }
        return validateTokenHelper.buildMosipUser(decodedJWT, jwtToken);
    }

    public MosipUserDto doOnlineTokenValidation(String token, WebClient webClient) {
		ImmutablePair<HttpStatus, MosipUserDto> validateResp = validateTokenHelper.doOnlineTokenValidation(token, webClient);

        if (validateResp.getLeft() == HttpStatus.EXPECTATION_FAILED || validateResp.getLeft() == HttpStatus.UNAUTHORIZED) {
            throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), 
                            AuthAdapterErrorCode.UNAUTHORIZED.getErrorMessage());
        }
        if (validateResp.getLeft() == HttpStatus.FORBIDDEN) { 
            throw new AuthManagerException(AuthAdapterErrorCode.FORBIDDEN.getErrorCode(), 
                            AuthAdapterErrorCode.FORBIDDEN.getErrorMessage());
        }
        if (validateResp.getLeft() != HttpStatus.OK) { 
            throw new AuthManagerException(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(), 
                            AuthAdapterErrorCode.UNAUTHORIZED.getErrorMessage());
        }

		return validateResp.getRight();
	}
}  