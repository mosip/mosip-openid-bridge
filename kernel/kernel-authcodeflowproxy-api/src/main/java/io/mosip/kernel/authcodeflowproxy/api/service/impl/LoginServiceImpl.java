package io.mosip.kernel.authcodeflowproxy.api.service.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import jakarta.servlet.http.Cookie;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.authcodeflowproxy.api.validator.ValidateTokenUtil;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.openid.bridge.api.constants.AuthErrorCode;
import io.mosip.kernel.openid.bridge.api.constants.Constants;
import io.mosip.kernel.openid.bridge.api.constants.Errors;
import io.mosip.kernel.openid.bridge.api.exception.AuthRestException;
import io.mosip.kernel.openid.bridge.api.exception.ClientException;
import io.mosip.kernel.openid.bridge.api.exception.ServiceException;
import io.mosip.kernel.authcodeflowproxy.api.service.LoginServiceV2;
import io.mosip.kernel.openid.bridge.api.utils.JWTUtils;
import io.mosip.kernel.openid.bridge.dto.AccessTokenResponse;
import io.mosip.kernel.openid.bridge.dto.AccessTokenResponseDTO;
import io.mosip.kernel.openid.bridge.dto.IAMErrorResponseDto;
import io.mosip.kernel.openid.bridge.dto.JWSSignatureRequestDto;
import io.mosip.kernel.openid.bridge.dto.JWTSignatureResponseDto;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;

@Service
public class LoginServiceImpl implements LoginServiceV2 {

	private static final String TOKEN_VALID = "TOKEN_VALID";

	@Value("${mosip.kernel.auth-code-url-splitter:#URISPLITTER#}")
	private String urlSplitter;

	@Value("${mosip.security.secure-cookie:false}")
	private boolean isSecureCookie;

	@Value("${auth.token.header:Authorization}")
	private String authTokenHeader;

	@Value("${auth.jwt.expiry:1800000}")
	private int authTokenExpiry;

	@Value("${mosip.iam.module.login_flow.name:authorization_code}")
	private String loginFlowName;

	@Value("${mosip.iam.module.clientid}")
	private String clientID;

	@Value("${mosip.iam.module.clientsecret}")
	private String clientSecret;

	@Value("${mosip.iam.module.redirecturi}")
	private String redirectURI;

	@Value("${mosip.iam.module.login_flow.scope:cls}")
	private String scope;

	@Value("${mosip.iam.module.login_flow.response_type:code}")
	private String responseType;

	@Value("${mosip.iam.authorization_endpoint}")
	private String authorizationEndpoint;

	@Value("${mosip.iam.module.admin_realm_id}")
	private String realmID;

	@Value("${mosip.iam.token_endpoint}")
	private String tokenEndpoint;

	@Value("${auth.server.admin.validate.url:}")
	private String validateUrl;
	
	
	@Value("${mosip.iam.post-logout-uri-param-key:post_logout_redirect_uri}")
	private String postLogoutRedirectURIParamKey;
	
	@Value("${mosip.iam.end-session-endpoint-path:/protocol/openid-connect/logout}")
	private String endSessionEndpointPath;

	@Value("${mosip.iam.module.token.endpoint.private-key-jwt.auth.enabled:false}")
	private boolean isJwtAuthEnabled;
	
	/**
	 * For offline logout, there is no token invalidation happening in the IdP's
	 * end. It is expected that the cookies with the tokens only getting expired.
	 */
	@Value("${mosip.iam.logout.offline:false}")
	private boolean offlineLogout;

	@Autowired
	private RestTemplate restTemplate;

	@Autowired(required = false)
	@Qualifier("selfTokenRestTemplate")
	private RestTemplate selfTokenRestTemplate;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private Environment environment;
	
	@Autowired
	private ValidateTokenUtil validateTokenUtil;

	@Override
	public String login(String redirectURI, String state) {
		return loginV2(redirectURI, state, null);
	}
	
	@Override
	public String loginV2(String redirectURI, String state, String uiLocales) {
		Map<String, String> pathParam = new HashMap<>();
		pathParam.put("realmId", realmID);
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(authorizationEndpoint);
		uriComponentsBuilder.queryParam(Constants.CLIENT_ID, clientID);
		uriComponentsBuilder.queryParam(Constants.REDIRECT_URI, this.redirectURI + redirectURI);
		uriComponentsBuilder.queryParam(Constants.STATE, state);
		uriComponentsBuilder.queryParam(Constants.RESPONSE_TYPE, responseType);
		uriComponentsBuilder.queryParam(Constants.SCOPE, scope);
		String claim = this.environment.getProperty(Constants.CLAIMS_PROPERTY);
		if(uiLocales != null){
			uriComponentsBuilder.queryParam(Constants.UI_LOCALES, uiLocales);
		}
		if(claim != null){
			uriComponentsBuilder.queryParam(Constants.CLAIMS, urlEncode(claim));
		}
		return uriComponentsBuilder.buildAndExpand(pathParam).toString();
	}

	private static String urlEncode(String value) {
	    try {
			return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			throw new ServiceException(Errors.UNSUPPORTED_ENCODING_EXCEPTION.getErrorCode(),
					Errors.UNSUPPORTED_ENCODING_EXCEPTION.getErrorMessage() + Constants.WHITESPACE + e.getMessage(), e);
		}
	}

	@Override
	public Cookie createCookie(String authCookie) {
		final Cookie cookie = new Cookie(authTokenHeader, authCookie);
		cookie.setMaxAge(authTokenExpiry);
		cookie.setHttpOnly(true);
		cookie.setSecure(isSecureCookie);
		cookie.setPath("/");
		return cookie;
	}
	
	@Override
	public Cookie createExpiringCookie() {
		final Cookie cookie = new Cookie(authTokenHeader, null);
		cookie.setMaxAge(0);
		cookie.setHttpOnly(true);
		cookie.setSecure(isSecureCookie);
		cookie.setPath("/");
		return cookie;
	}

	@Override
	public Object valdiateToken(String authToken) {
		//For IdP if validateURL is null/empty, no need for online token validation (which is done through authmanager), perform it offline.
		if(validateUrl == null || validateUrl.isEmpty()) {
			ImmutablePair<Boolean, AuthErrorCode> tokenValid = validateTokenUtil.isTokenValid(authToken);
			if(tokenValid.left) {
				return TOKEN_VALID;
			} else {
				throw new AuthRestException(
						List.of(new ServiceError(tokenValid.right.getErrorCode(), tokenValid.right.getErrorMessage())),
						HttpStatus.UNAUTHORIZED);
			}
		}
		HttpHeaders headers = new HttpHeaders();
		headers.add("Cookie", authTokenHeader + "=" + authToken);
		HttpEntity<String> requestEntity = new HttpEntity<>(headers);
		ResponseEntity<String> response = null;
		try {
			response = restTemplate.exchange(validateUrl, HttpMethod.GET, requestEntity, String.class);
		} catch (HttpClientErrorException | HttpServerErrorException e) {
			String responseBody = e.getResponseBodyAsString();
			List<ServiceError> validationErrorList = ExceptionUtils.getServiceErrorList(responseBody);

			if (!validationErrorList.isEmpty()) {
				throw new AuthRestException(validationErrorList, HttpStatus.valueOf(e.getStatusCode().value()));
			} else {
				throw new ServiceException(Errors.REST_EXCEPTION.getErrorCode(), e.getResponseBodyAsString());
			}

		}
		String responseBody = response.getBody();
		List<ServiceError> validationErrorList = ExceptionUtils.getServiceErrorList(responseBody);

		if (!validationErrorList.isEmpty()) {
			throw new AuthRestException(validationErrorList, HttpStatus.valueOf(response.getStatusCode().value()));
		}
		ResponseWrapper<?> responseObject;
		MosipUserDto mosipUserDto;
		try {
			responseObject = objectMapper.readValue(response.getBody(), ResponseWrapper.class);
			mosipUserDto = objectMapper.readValue(objectMapper.writeValueAsString(responseObject.getResponse()),
					MosipUserDto.class);
		} catch (IOException e) {
			throw new ServiceException(Errors.IO_EXCEPTION.getErrorCode(), Errors.IO_EXCEPTION.getErrorMessage());
		}
		return mosipUserDto;
	}

	@Override
	public AccessTokenResponseDTO loginRedirect(String state, String sessionState, String code, String stateCookie,
												String redirectURI) {
		// Compare states
		if (!stateCookie.equals(state)) {
			throw new ClientException(Errors.STATE_EXCEPTION.getErrorCode(), Errors.STATE_EXCEPTION.getErrorMessage());
		}

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add(Constants.GRANT_TYPE, loginFlowName);
		map.add(Constants.CLIENT_ID, clientID);
		if(isJwtAuthEnabled){
			map.add(Constants.CLIENT_ASSERTION, getClientAssertion());
			map.add(Constants.CLIENT_ASSERTION_TYPE, this.environment.getProperty(Constants.CLIENT_ASSERTION_TYPE_PROPERTY));
		} else{
			map.add(Constants.CLIENT_SECRET, clientSecret);
		}
		map.add(Constants.CODE, code);
		map.add(Constants.REDIRECT_URI, this.redirectURI + redirectURI);
		Map<String, String> pathParam = new HashMap<>();
		pathParam.put("realmId", realmID);
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(tokenEndpoint);
		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
		ResponseEntity<String> responseEntity = null;
		try {
			responseEntity = restTemplate.exchange(uriBuilder.buildAndExpand(pathParam).toUriString(), HttpMethod.POST,
					entity, String.class);

		} catch (HttpClientErrorException | HttpServerErrorException e) {
			IAMErrorResponseDto keycloakErrorResponseDto = parseKeyClockErrorResponse(e);

			throw new ServiceException(Errors.ACESSTOKEN_EXCEPTION.getErrorCode(),
					Errors.ACESSTOKEN_EXCEPTION.getErrorMessage() + Constants.WHITESPACE
							+ keycloakErrorResponseDto.getError_description(), e);
		}
		AccessTokenResponse accessTokenResponse = null;
		try {
			accessTokenResponse = objectMapper.readValue(responseEntity.getBody(), AccessTokenResponse.class);
		} catch (IOException exception) {
			throw new ServiceException(Errors.RESPONSE_PARSE_ERROR.getErrorCode(),
					Errors.RESPONSE_PARSE_ERROR.getErrorMessage() + Constants.WHITESPACE + exception.getMessage(), exception);
		}
		AccessTokenResponseDTO accessTokenResponseDTO = new AccessTokenResponseDTO();
		accessTokenResponseDTO.setAccessToken(accessTokenResponse.getAccess_token());
		accessTokenResponseDTO.setExpiresIn(accessTokenResponse.getExpires_in());
		accessTokenResponseDTO.setIdToken(accessTokenResponse.getId_token());
		return accessTokenResponseDTO;
	}

	private String getClientAssertion() {
		JWSSignatureRequestDto jwsSignatureRequestDto = new JWSSignatureRequestDto();
		try {
			jwsSignatureRequestDto.setDataToSign( CryptoUtil.encodeToPlainBase64(getClientAssertionData()));
			jwsSignatureRequestDto.setReferenceId(this.environment.getProperty(Constants.CLIENT_ASSERTION_REFERENCE_ID));
			jwsSignatureRequestDto.setApplicationId(this.environment.getProperty(Constants.APPLICATION_ID));
			jwsSignatureRequestDto.setIncludePayload(Boolean.valueOf(this.environment.getProperty(Constants.IS_INCLUDE_PAYLOAD)));
			jwsSignatureRequestDto.setIncludeCertificate(Boolean.valueOf(this.environment.getProperty(Constants.IS_INCLUDE_CERTIFICATE)));
			jwsSignatureRequestDto.setIncludeCertHash(Boolean.valueOf(this.environment.getProperty(Constants.IS_iNCLUDE_CERT_HASH)));

			RequestWrapper<JWSSignatureRequestDto> requestWrapper = new RequestWrapper<>();
			requestWrapper.setRequest(jwsSignatureRequestDto);
			requestWrapper.setRequesttime(DateUtils.getUTCCurrentDateTime());
			HttpEntity<RequestWrapper<JWSSignatureRequestDto>> requestWrapperHttpEntity = new HttpEntity<>(requestWrapper);
			ResponseWrapper<?> responseWrapper =
					selfTokenRestTemplate.exchange(URI.create(Objects.requireNonNull(this.environment.getProperty(Constants.KEYMANAGER_JWT_SIGN_END_POINT))),
							HttpMethod.POST, requestWrapperHttpEntity, ResponseWrapper.class).getBody();
			Object responseObject = Objects.requireNonNull(responseWrapper).getResponse();
			JWTSignatureResponseDto responseDto= objectMapper.convertValue(responseObject, JWTSignatureResponseDto.class);
			return responseDto.getJwtSignedData();
		} catch (HttpClientErrorException | HttpServerErrorException e) {
			throw new ServiceException(Errors.JWT_SIGN_EXCEPTION.getErrorCode(),
					Errors.JWT_SIGN_EXCEPTION.getErrorMessage());
		}
	}

	private byte[] getClientAssertionData() {
		Map dataToSignMap = new LinkedHashMap();
		dataToSignMap.put(Constants.SUB, clientID);
		dataToSignMap.put(Constants.ISS, clientID);
		dataToSignMap.put(Constants.AUD, tokenEndpoint);
		dataToSignMap.put(Constants.EXP, getExpiryTime());
		dataToSignMap.put(Constants.IAT, getEpochTime());
		String jsonObject = null;
		try {
			jsonObject = objectMapper.writeValueAsString(dataToSignMap);
		} catch (JsonProcessingException e) {
			throw new ServiceException(Errors.JSON_PROCESSING_EXCEPTION.getErrorCode(),
					Errors.JSON_PROCESSING_EXCEPTION.getErrorMessage());
		}
		return jsonObject.getBytes();
	}

	private Object getEpochTime() {
		Instant instant = Instant.now();
		return instant.getEpochSecond();
	}

	private Object getExpiryTime() {
		int expirySec = Integer.parseInt(Objects.requireNonNull(this.environment.getProperty(Constants.JWT_EXPIRY_TIME)));
		Instant instant = Instant.now().plusSeconds(expirySec);
		return instant.getEpochSecond();
	}

	private IAMErrorResponseDto parseKeyClockErrorResponse(HttpStatusCodeException exception) {
		IAMErrorResponseDto keycloakErrorResponseDto = null;
		try {
			keycloakErrorResponseDto = objectMapper.readValue(exception.getResponseBodyAsString(),
					IAMErrorResponseDto.class);

		} catch (IOException e) {
			throw new ServiceException(Errors.RESPONSE_PARSE_ERROR.getErrorCode(),
					Errors.RESPONSE_PARSE_ERROR.getErrorMessage() + Constants.WHITESPACE + e.getMessage());
		}
		return keycloakErrorResponseDto;
	}

	@Override
	public String logoutUser(String token,String redirectURI) {
		if (EmptyCheckUtils.isNullEmpty(token)) {
			throw new AuthenticationServiceException(Errors.INVALID_TOKEN.getErrorMessage());
		}
		
		if(offlineLogout) {
			return new String(Base64.decodeBase64(redirectURI.getBytes()));
		}
		
		String issuer = JWTUtils.getissuer(token);
		StringBuilder urlBuilder = new StringBuilder().append(issuer).append(endSessionEndpointPath);
		UriComponentsBuilder uriComponentsBuilder;
		try {
			uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString())
					.queryParam(postLogoutRedirectURIParamKey, URLEncoder.encode(redirectURI, StandardCharsets.UTF_8.toString()));
		} catch (UnsupportedEncodingException e) {
			throw new ServiceException(Errors.UNSUPPORTED_ENCODING_EXCEPTION.getErrorCode(),
					Errors.UNSUPPORTED_ENCODING_EXCEPTION.getErrorMessage() + Constants.WHITESPACE + e.getMessage(), e);
		}
		return uriComponentsBuilder.build().toString();
	}

}
