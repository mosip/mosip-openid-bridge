package io.mosip.kernel.auth.defaultimpl.service.impl;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultimpl.config.MosipEnvironment;
import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.constant.AuthErrorCode;
import io.mosip.kernel.auth.defaultimpl.dto.AccessTokenResponse;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpEmailSendResponseDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpGenerateRequest;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpGenerateResponseDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpSmsSendRequestDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpTemplateDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpTemplateResponseDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpValidatorResponseDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.SmsResponseDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.email.OTPEmailTemplate;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerServiceException;
import io.mosip.kernel.auth.defaultimpl.service.OTPGenerateService;
import io.mosip.kernel.auth.defaultimpl.service.OTPService;
import io.mosip.kernel.auth.defaultimpl.util.MemoryCache;
import io.mosip.kernel.auth.defaultimpl.util.OtpValidator;
import io.mosip.kernel.auth.defaultimpl.util.TemplateUtil;
import io.mosip.kernel.core.authmanager.exception.AuthNException;
import io.mosip.kernel.core.authmanager.exception.AuthZException;
import io.mosip.kernel.core.authmanager.model.AuthNResponseDto;
import io.mosip.kernel.core.authmanager.model.MosipUserDto;
import io.mosip.kernel.core.authmanager.model.MosipUserTokenDto;
import io.mosip.kernel.core.authmanager.model.OtpUser;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;

/**
 * @author Ramadurai Pandian
 *
 */

@Profile("!local")
@Service
public class OTPServiceImpl implements OTPService {

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.auth.service.OTPService#sendOTP(io.mosip.kernel.auth.
	 * entities.MosipUserDto, java.lang.String)
	 */

	@Qualifier("authRestTemplate")
	@Autowired
	RestTemplate restTemplate;

	@Autowired
	MosipEnvironment mosipEnvironment;

	@Autowired
	OTPGenerateService oTPGenerateService;

	@Autowired
	private ObjectMapper mapper;

	@Autowired
	private TemplateUtil templateUtil;

	@Autowired
	private OtpValidator authOtpValidator;

	@Value("${mosip.iam.open-id-url}")
	private String keycloakOpenIdUrl;

	@Value("${mosip.iam.default.realm-id}")
	private String realmId;

	@Value("${mosip.kernel.auth.client.id}")
	private String authClientID;

	@Value("${mosip.kernel.prereg.client.id}")
	private String preregClientId;

	@Value("${mosip.kernel.prereg.secret.key}")
	private String preregSecretKey;

	@Value("${mosip.kernel.auth.secret.key}")
	private String authSecret;

	@Value("${mosip.kernel.ida.client.id}")
	private String idaClientID;

	@Value("${mosip.kernel.ida.secret.key}")
	private String idaSecret;

	@Value("${mosip.admin.clientid}")
	private String mosipAdminClientID;

	@Value("${mosip.admin.clientsecret}")
	private String mosipAdminSecret;

	@Value("${mosip.iam.pre-reg_user_password}")
	private String preRegUserPassword;

	@Value("${mosip.kernel.prereg.realm-id}")
	private String preregRealmId;

	private SmsResponseDto sendOtpBySms(String message, String mobile, String token) {
		try {
			List<ServiceError> validationErrorsList = null;
			OtpSmsSendRequestDto otpSmsSendRequestDto = new OtpSmsSendRequestDto(mobile, message);
			SmsResponseDto otpSmsSendResponseDto = null;
			String url = mosipEnvironment.getOtpSenderSmsApi();
			RequestWrapper<OtpSmsSendRequestDto> reqWrapper = new RequestWrapper<>();
			reqWrapper.setRequesttime(LocalDateTime.now());
			reqWrapper.setRequest(otpSmsSendRequestDto);
			HttpHeaders headers = new HttpHeaders();
			headers.set(AuthConstant.COOKIE, AuthConstant.AUTH_HEADER + token);
			ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST,
					new HttpEntity<Object>(reqWrapper, headers), String.class);
			validationErrorsList = ExceptionUtils.getServiceErrorList(response.getBody());
			if (!validationErrorsList.isEmpty()) {
				throw new AuthManagerServiceException(validationErrorsList);
			}
			ResponseWrapper<?> responseObject;
			try {
				responseObject = mapper.readValue(response.getBody(), ResponseWrapper.class);
				otpSmsSendResponseDto = mapper.readValue(mapper.writeValueAsString(responseObject.getResponse()),
						SmsResponseDto.class);
			} catch (Exception e) {
				throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), e.getMessage());
			}
			return otpSmsSendResponseDto;
		} catch (HttpClientErrorException | HttpServerErrorException e) {
			String errmessage = e.getResponseBodyAsString();
			throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), errmessage);
		}
	}

	@Override
	public MosipUserTokenDto validateOTP(MosipUserDto mosipUser, String otp, String appId) {
		String key = new OtpGenerateRequest(mosipUser).getKey();
		MosipUserTokenDto mosipUserDtoToken = null;
		ResponseEntity<String> response = null;
		final String url = mosipEnvironment.getVerifyOtpUserApi();
		String token = null;
		AccessTokenResponse accessTokenResponse = null;
		AccessTokenResponse responseAccessTokenResponse = null;
		String realm = appId;
		try {
			accessTokenResponse = getAuthAccessToken(authClientID, authSecret, realmId);
			if (accessTokenResponse != null)
				token = accessTokenResponse.getAccess_token();
			else {
				throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), "response is null");
			}
		} catch (Exception e) {
			throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), e.getMessage(), e);
		}
		UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url).queryParam("key", key).queryParam("otp",
				otp);
		HttpHeaders headers = new HttpHeaders();
		headers.set(AuthConstant.COOKIE, AuthConstant.AUTH_HEADER + token);
		response = restTemplate.exchange(builder.toUriString(), HttpMethod.GET, new HttpEntity<Object>(headers),
				String.class);
		if (response.getStatusCode().equals(HttpStatus.OK)) {
			String responseBody = response.getBody();
			List<ServiceError> validationErrorsList = null;
			validationErrorsList = ExceptionUtils.getServiceErrorList(responseBody);

			if (!validationErrorsList.isEmpty()) {
				throw new AuthManagerServiceException(validationErrorsList);
			}
			responseAccessTokenResponse = getUserAccessToken(mosipUser.getUserId(), realm);
			OtpValidatorResponseDto otpResponse = null;
			ResponseWrapper<?> responseObject;
			try {
				responseObject = mapper.readValue(response.getBody(), ResponseWrapper.class);
				otpResponse = mapper.readValue(mapper.writeValueAsString(responseObject.getResponse()),
						OtpValidatorResponseDto.class);
			} catch (Exception e) {
				throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), e.getMessage(), e);
			}
			if (otpResponse.getStatus() != null && otpResponse.getStatus().equals("success")) {
				String expTime = accessTokenResponse.getExpires_in();
				if (responseAccessTokenResponse != null) {
					mosipUserDtoToken = new MosipUserTokenDto(mosipUser, responseAccessTokenResponse.getAccess_token(),
							responseAccessTokenResponse.getRefresh_token(), Long.parseLong(expTime), null, null,
							Long.parseLong(accessTokenResponse.getRefresh_expires_in()));
				} else {
					throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), "response is null");
				}
				mosipUserDtoToken.setMessage(otpResponse.getMessage());
				mosipUserDtoToken.setStatus(otpResponse.getStatus());
			} else {
				mosipUserDtoToken = new MosipUserTokenDto();
				mosipUserDtoToken.setMessage(otpResponse.getMessage());
				mosipUserDtoToken.setStatus(otpResponse.getStatus());
			}

		}
		return mosipUserDtoToken;
	}

	@Override
	public AuthNResponseDto sendOTPForUin(MosipUserDto mosipUser, OtpUser otpUser, String appId) {
		AuthNResponseDto authNResponseDto = null;
		OtpEmailSendResponseDto otpEmailSendResponseDto = null;
		SmsResponseDto otpSmsSendResponseDto = null;
		String mobileMessage = null;
		OTPEmailTemplate emailTemplate = null;
		AccessTokenResponse accessTokenResponse = null;
		authOtpValidator.validateOTPUser(otpUser);
		try {
			// token = tokenService.getInternalTokenGenerationService();
			accessTokenResponse = getAuthAccessToken(idaClientID, idaSecret, appId);
		} catch (HttpClientErrorException | HttpServerErrorException ex) {
			List<ServiceError> validationErrorsList = ExceptionUtils.getServiceErrorList(ex.getResponseBodyAsString());

			if (ex.getRawStatusCode() == 401) {
				if (!validationErrorsList.isEmpty()) {
					throw new AuthNException(validationErrorsList);
				} else {
					throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(),
							AuthErrorCode.CLIENT_ERROR.getErrorMessage(), ex);
				}
			}
			if (ex.getRawStatusCode() == 403) {
				if (!validationErrorsList.isEmpty()) {
					throw new AuthZException(validationErrorsList);
				} else {
					throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), ex.getMessage(), ex);
				}
			}
			if (!validationErrorsList.isEmpty()) {
				throw new AuthManagerServiceException(validationErrorsList);
			} else {
				throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), ex.getMessage(), ex);
			}
		}
		OtpGenerateResponseDto otpGenerateResponseDto = null;
		if (accessTokenResponse != null) {
			otpGenerateResponseDto = oTPGenerateService.generateOTP(mosipUser, accessTokenResponse.getAccess_token());
		} else {
			throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), "response is null");
		}
		if (otpGenerateResponseDto != null && otpGenerateResponseDto.getStatus().equals("USER_BLOCKED")) {
			authNResponseDto = new AuthNResponseDto();
			authNResponseDto.setStatus(AuthConstant.FAILURE_STATUS);
			authNResponseDto.setMessage(otpGenerateResponseDto.getStatus());
			return authNResponseDto;
		}
		if (otpGenerateResponseDto != null) {
			for (String channel : otpUser.getOtpChannel()) {
				switch (channel.toLowerCase()) {
				case AuthConstant.EMAIL:
					emailTemplate = templateUtil.getEmailTemplate(otpGenerateResponseDto.getOtp(), otpUser,
							accessTokenResponse.getAccess_token());
					otpEmailSendResponseDto = sendOtpByEmail(emailTemplate, mosipUser.getMail(),
							accessTokenResponse.getAccess_token());
					break;
				case AuthConstant.PHONE:
					mobileMessage = templateUtil.getOtpSmsMessage(otpGenerateResponseDto.getOtp(), otpUser,
							accessTokenResponse.getAccess_token());
					otpSmsSendResponseDto = sendOtpBySms(mobileMessage, mosipUser.getMobile(),
							accessTokenResponse.getAccess_token());
					break;
				}
			}
		}

		if (otpEmailSendResponseDto != null && otpSmsSendResponseDto != null) {
			authNResponseDto = new AuthNResponseDto();
			authNResponseDto.setStatus(AuthConstant.SUCCESS_STATUS);
			authNResponseDto.setMessage(AuthConstant.ALL_CHANNELS_MESSAGE);
		} else if (otpEmailSendResponseDto != null) {
			authNResponseDto = new AuthNResponseDto();
			authNResponseDto.setStatus(otpEmailSendResponseDto.getStatus());
			authNResponseDto.setMessage(otpEmailSendResponseDto.getMessage());
		} else if (otpSmsSendResponseDto != null) {
			authNResponseDto = new AuthNResponseDto();
			authNResponseDto.setStatus(otpSmsSendResponseDto.getStatus());
			authNResponseDto.setMessage(otpSmsSendResponseDto.getMessage());
		}
		return authNResponseDto;
	}

	@Override
	public AuthNResponseDto sendOTP(MosipUserDto mosipUser, OtpUser otpUser, String appId) throws Exception {
		AuthNResponseDto authNResponseDto = null;
		OtpEmailSendResponseDto otpEmailSendResponseDto = null;
		SmsResponseDto otpSmsSendResponseDto = null;
		String mobileMessage = null;
		OTPEmailTemplate emailTemplate = null;
		AccessTokenResponse accessTokenResponse = null;
		authOtpValidator.validateOTPUser(otpUser);
		try {
			accessTokenResponse = getAuthAccessToken(authClientID, authSecret, appId);
		} catch (HttpClientErrorException | HttpServerErrorException ex) {
			List<ServiceError> validationErrorsList = ExceptionUtils.getServiceErrorList(ex.getResponseBodyAsString());

			if (ex.getRawStatusCode() == 401) {
				if (!validationErrorsList.isEmpty()) {
					throw new AuthNException(validationErrorsList);
				} else {
					throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(),
							AuthErrorCode.CLIENT_ERROR.getErrorMessage(), ex);
				}
			}
			if (ex.getRawStatusCode() == 403) {
				if (!validationErrorsList.isEmpty()) {
					throw new AuthZException(validationErrorsList);
				} else {
					throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), ex.getMessage(), ex);
				}
			}
			if (!validationErrorsList.isEmpty()) {
				throw new AuthManagerServiceException(validationErrorsList);
			} else {
				throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), ex.getMessage(), ex);
			}
		}
		OtpGenerateResponseDto otpGenerateResponseDto = null;
		if (accessTokenResponse != null) {
			otpGenerateResponseDto = oTPGenerateService.generateOTP(mosipUser, accessTokenResponse.getAccess_token());
		} else {
			throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), "response is null");
		}
		if (otpGenerateResponseDto != null && otpGenerateResponseDto.getStatus().equals("USER_BLOCKED")) {
			authNResponseDto = new AuthNResponseDto();
			authNResponseDto.setStatus(AuthConstant.FAILURE_STATUS);
			authNResponseDto.setMessage(otpGenerateResponseDto.getStatus());
			return authNResponseDto;
		}
		if (otpGenerateResponseDto != null) {
			for (String channel : otpUser.getOtpChannel()) {
				switch (channel.toLowerCase()) {
				case AuthConstant.EMAIL:
					emailTemplate = templateUtil.getEmailTemplate(otpGenerateResponseDto.getOtp(), otpUser,
							accessTokenResponse.getAccess_token());
					otpEmailSendResponseDto = sendOtpByEmail(emailTemplate, mosipUser.getUserId(),
							accessTokenResponse.getAccess_token());
					break;
				case AuthConstant.PHONE:
					mobileMessage = templateUtil.getOtpSmsMessage(otpGenerateResponseDto.getOtp(), otpUser,
							accessTokenResponse.getAccess_token());
					otpSmsSendResponseDto = sendOtpBySms(mobileMessage, mosipUser.getUserId(),
							accessTokenResponse.getAccess_token());
					break;
				}
			}
		}
		if (otpEmailSendResponseDto != null && otpSmsSendResponseDto != null) {
			authNResponseDto = new AuthNResponseDto();
			authNResponseDto.setStatus(AuthConstant.SUCCESS_STATUS);
			authNResponseDto.setMessage(AuthConstant.ALL_CHANNELS_MESSAGE);
		} else if (otpEmailSendResponseDto != null) {
			authNResponseDto = new AuthNResponseDto();
			authNResponseDto.setStatus(otpEmailSendResponseDto.getStatus());
			authNResponseDto.setMessage(otpEmailSendResponseDto.getMessage());
		} else if (otpSmsSendResponseDto != null) {
			authNResponseDto = new AuthNResponseDto();
			authNResponseDto.setStatus(otpSmsSendResponseDto.getStatus());
			authNResponseDto.setMessage(otpSmsSendResponseDto.getMessage());
		}
		return authNResponseDto;
	}

	private OtpEmailSendResponseDto sendOtpByEmail(OTPEmailTemplate emailTemplate, String email, String token) {
		ResponseEntity<String> response = null;
		String url = mosipEnvironment.getOtpSenderEmailApi();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.MULTIPART_FORM_DATA);
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON_UTF8));
		OtpEmailSendResponseDto otpEmailSendResponseDto = null;
		headers.set(AuthConstant.COOKIE, AuthConstant.AUTH_HEADER + token);
		MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
		map.add("mailTo", email);
		map.add("mailSubject", emailTemplate.getEmailSubject());
		map.add("mailContent", emailTemplate.getEmailContent());
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(map, headers);
		try {
			response = restTemplate.exchange(url, HttpMethod.POST, request, String.class);
			if (response.getStatusCode().equals(HttpStatus.OK)) {
				String responseBody = response.getBody();
				List<ServiceError> validationErrorsList = null;
				validationErrorsList = ExceptionUtils.getServiceErrorList(responseBody);
				if (!validationErrorsList.isEmpty()) {
					throw new AuthManagerServiceException(validationErrorsList);
				}
				ResponseWrapper<?> responseObject;
				try {
					responseObject = mapper.readValue(response.getBody(), ResponseWrapper.class);
					otpEmailSendResponseDto = mapper.readValue(mapper.writeValueAsString(responseObject.getResponse()),
							OtpEmailSendResponseDto.class);
				} catch (Exception e) {
					throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), e.getMessage(), e);
				}
			}
		} catch (HttpClientErrorException | HttpServerErrorException ex) {
			List<ServiceError> validationErrorsList = ExceptionUtils.getServiceErrorList(ex.getResponseBodyAsString());

			if (ex.getRawStatusCode() == 401) {
				if (!validationErrorsList.isEmpty()) {
					throw new AuthNException(validationErrorsList);
				} else {
					throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(),
							AuthErrorCode.CLIENT_ERROR.getErrorMessage(), ex);
				}
			}
			if (ex.getRawStatusCode() == 403) {
				if (!validationErrorsList.isEmpty()) {
					throw new AuthZException(validationErrorsList);
				} else {
					throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), ex.getMessage(), ex);
				}
			}
			if (!validationErrorsList.isEmpty()) {
				throw new AuthManagerServiceException(validationErrorsList);
			} else {
				throw new AuthManagerException(AuthErrorCode.CLIENT_ERROR.getErrorCode(), ex.getMessage(), ex);
			}
		}
		return otpEmailSendResponseDto;
	}

	private AccessTokenResponse getUserAccessToken(String username, String realm) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> tokenRequestBody = null;
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, realm);
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		tokenRequestBody = getAdminValueMap(username, realm);
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(tokenRequestBody, headers);
		ResponseEntity<AccessTokenResponse> response = restTemplate.postForEntity(
				uriComponentsBuilder.buildAndExpand(pathParams).toUriString(), request, AccessTokenResponse.class);
		return response.getBody();
	}

	private AccessTokenResponse getAuthAccessToken(String clientID, String clientSecret, String realmId) {
		HttpHeaders headers = new HttpHeaders();
		if (realmId.equalsIgnoreCase(preregRealmId)) {
			clientID = preregClientId;
			clientSecret = preregSecretKey;
		}
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> tokenRequestBody = null;
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, realmId);

		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		tokenRequestBody = getClientValueMap(clientID, clientSecret);
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(tokenRequestBody, headers);
		ResponseEntity<AccessTokenResponse> response = restTemplate.postForEntity(
				uriComponentsBuilder.buildAndExpand(pathParams).toUriString(), request, AccessTokenResponse.class);
		return response.getBody();
	}

	private MultiValueMap<String, String> getAdminValueMap(String username, String realm) {
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		if (realm.equalsIgnoreCase(preregRealmId)) {
			map.add(AuthConstant.CLIENT_ID, preregClientId);
			map.add(AuthConstant.CLIENT_SECRET, preregSecretKey);
		} else {
			map.add(AuthConstant.CLIENT_ID, mosipAdminClientID);
			map.add(AuthConstant.CLIENT_SECRET, mosipAdminSecret);
		}
		map.add(AuthConstant.GRANT_TYPE, AuthConstant.PASSWORDCONSTANT);
		map.add(AuthConstant.USER_NAME, username);
		map.add(AuthConstant.PASSWORDCONSTANT, preRegUserPassword);
		return map;
	}

	private MultiValueMap<String, String> getClientValueMap(String clientID, String clientSecret) {
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add(AuthConstant.GRANT_TYPE, AuthConstant.CLIENT_CREDENTIALS);
		map.add(AuthConstant.CLIENT_ID, clientID);
		map.add(AuthConstant.CLIENT_SECRET, clientSecret);
		return map;
	}
}
