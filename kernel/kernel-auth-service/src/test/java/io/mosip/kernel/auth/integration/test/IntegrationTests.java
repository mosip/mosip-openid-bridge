package io.mosip.kernel.auth.integration.test;

import static org.hamcrest.CoreMatchers.is;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultimpl.config.MosipEnvironment;
import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.constant.KeycloakConstants;
import io.mosip.kernel.auth.defaultimpl.dto.AccessTokenResponse;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpValidatorResponseDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.email.OTPEmailTemplate;
import io.mosip.kernel.auth.defaultimpl.dto.otp.idrepo.ResponseDTO;
import io.mosip.kernel.auth.defaultimpl.repository.UserStoreFactory;
import io.mosip.kernel.auth.defaultimpl.repository.impl.KeycloakImpl;
import io.mosip.kernel.auth.defaultimpl.service.OTPService;
import io.mosip.kernel.auth.defaultimpl.service.TokenService;
import io.mosip.kernel.auth.defaultimpl.service.UinService;
import io.mosip.kernel.auth.defaultimpl.util.TemplateUtil;
import io.mosip.kernel.auth.defaultimpl.util.TokenGenerator;
import io.mosip.kernel.auth.defaultimpl.util.TokenValidator;
import io.mosip.kernel.auth.test.AuthTestBootApplication;
import io.mosip.kernel.core.authmanager.model.LoginUser;
import io.mosip.kernel.core.authmanager.model.MosipUserDto;
import io.mosip.kernel.core.authmanager.model.OtpUser;
import io.mosip.kernel.core.authmanager.model.RefreshTokenRequest;
import io.mosip.kernel.core.authmanager.model.UserOtp;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class IntegrationTests {

	@Value("${mosip.iam.open-id-url}")
	private String keycloakOpenIdUrl;

	@Value("${mosip.iam.realm.operations.base-url}")
	private String keycloakBaseUrl;

	@Autowired
	UserStoreFactory userStoreFactory;

	@Autowired
	KeycloakImpl keycloakImpl;

	@Autowired
	TokenGenerator tokenGenerator;

	@Autowired
	TokenValidator tokenValidator;

	@Autowired
	TokenService customTokenServices;

	@Autowired
	OTPService oTPService;

	@Autowired
	UinService uinService;

	@Qualifier("authRestTemplate")
	@MockBean
	RestTemplate authRestTemplate;

	@Qualifier(value = "keycloakRestTemplate")
	@MockBean
	private RestTemplate keycloakRestTemplate;

	@Value("${mosip.iam.base-url}")
	private String keycloakBaseURL;

	@MockBean
	private TemplateUtil templateUtil;

	@Autowired
	MosipEnvironment mosipEnvironment;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ObjectMapper objectMapper;

	@Before
	public void init() {

	}

	@Test
	public void sendOTPUINPhoneTest() throws Exception {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);
		// uin
		Map<String, String> uriParams = new HashMap<String, String>();
		uriParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "112211");
		String uinEntityURL = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uriParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);
		when(authRestTemplate.exchange(Mockito.eq(uinEntityURL), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));

		final String url = mosipEnvironment.getGenerateOtpApi();
		String otpResponse = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"otp\": \"820121\",\r\n" + "    \"status\": \"SUCCESS\"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getOTPRespo = ResponseEntity.ok(otpResponse);
		when(authRestTemplate.postForEntity(Mockito.eq(url), Mockito.any(), Mockito.eq(String.class)))
				.thenReturn(getOTPRespo);
		when(templateUtil.getOtpSmsMessage(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("MOCK_MESSAGE");
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		RequestWrapper<OtpUser> otpUserDto = new RequestWrapper<OtpUser>();
		otpUserDto.setRequest(otpUser);
		mockMvc.perform(post("/authenticate/sendotp").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(otpUserDto))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("SUCCESS")));
	}

	@Test
	public void sendOTPUINEmailTest() throws Exception {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);
		// uin
		Map<String, String> uriParams = new HashMap<String, String>();
		uriParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "112211");
		String uinEntityURL = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uriParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);
		when(authRestTemplate.exchange(Mockito.eq(uinEntityURL), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));

		final String url = mosipEnvironment.getGenerateOtpApi();
		String otpResponse = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"otp\": \"820121\",\r\n" + "    \"status\": \"SUCCESS\"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getOTPRespo = ResponseEntity.ok(otpResponse);
		when(authRestTemplate.postForEntity(Mockito.eq(url), Mockito.any(), Mockito.eq(String.class)))
				.thenReturn(getOTPRespo);
		// email and Template
		OTPEmailTemplate emailTemplate = new OTPEmailTemplate();
		emailTemplate.setEmailContent("mock-email");
		emailTemplate.setEmailSubject("mock-subject");
		emailTemplate.setEmailTo("mock@mosip.io");
		when(templateUtil.getEmailTemplate(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(emailTemplate);
		String emailUrl = mosipEnvironment.getOtpSenderEmailApi();
		String emailResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getEmailRespo = ResponseEntity.ok(emailResp);
		when(authRestTemplate.exchange(Mockito.eq(emailUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getEmailRespo);
		List<String> channel = new ArrayList<>();
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		RequestWrapper<OtpUser> otpUserDto = new RequestWrapper<OtpUser>();
		otpUserDto.setRequest(otpUser);
		mockMvc.perform(post("/authenticate/sendotp").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(otpUserDto))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("SUCCESS")));
	}

	@Test
	public void sendOTPUINEmailPhoneTest() throws Exception {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);
		// uin
		Map<String, String> uriParams = new HashMap<String, String>();
		uriParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "112211");
		String uinEntityURL = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uriParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);
		when(authRestTemplate.exchange(Mockito.eq(uinEntityURL), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));

		final String url = mosipEnvironment.getGenerateOtpApi();
		String otpResponse = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"otp\": \"820121\",\r\n" + "    \"status\": \"SUCCESS\"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getOTPRespo = ResponseEntity.ok(otpResponse);
		when(authRestTemplate.postForEntity(Mockito.eq(url), Mockito.any(), Mockito.eq(String.class)))
				.thenReturn(getOTPRespo);
		// sms
		when(templateUtil.getOtpSmsMessage(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("MOCK_MESSAGE");
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);

		// email and Template
		OTPEmailTemplate emailTemplate = new OTPEmailTemplate();
		emailTemplate.setEmailContent("mock-email");
		emailTemplate.setEmailSubject("mock-subject");
		emailTemplate.setEmailTo("mock@mosip.io");
		when(templateUtil.getEmailTemplate(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(emailTemplate);
		String emailUrl = mosipEnvironment.getOtpSenderEmailApi();
		String emailResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getEmailRespo = ResponseEntity.ok(emailResp);
		when(authRestTemplate.exchange(Mockito.eq(emailUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getEmailRespo);

		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		RequestWrapper<OtpUser> otpUserDto = new RequestWrapper<OtpUser>();
		otpUserDto.setRequest(otpUser);
		mockMvc.perform(post("/authenticate/sendotp").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(otpUserDto))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("success")));
	}

	@Test
	public void sendOTPEmailTest() throws Exception {
		// is user already present
		Map<String, String> registerPathParams = new HashMap<>();
		registerPathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users?username=").concat("112211"));

		String userIDResp = "[\r\n" + "  {\r\n" + "    \"username\": \"112211\",\r\n" + "    \"id\": \"8282828282\"\r\n"
				+ "  }\r\n" + "]";
		when(keycloakRestTemplate.exchange(
				Mockito.eq(uriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));

		// register user

		UriComponentsBuilder registerUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users"));
		when(keycloakRestTemplate.exchange(
				Mockito.eq(registerUriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.POST), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok("{}"));

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder accessTokenuriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(
				Mockito.eq(accessTokenuriComponentsBuilder.buildAndExpand(pathParams).toUriString()), Mockito.any(),
				Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);

		final String url = mosipEnvironment.getGenerateOtpApi();
		String otpResponse = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"otp\": \"820121\",\r\n" + "    \"status\": \"SUCCESS\"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getOTPRespo = ResponseEntity.ok(otpResponse);
		when(authRestTemplate.postForEntity(Mockito.eq(url), Mockito.any(), Mockito.eq(String.class)))
				.thenReturn(getOTPRespo);
		// email
		OTPEmailTemplate emailTemplate = new OTPEmailTemplate();
		emailTemplate.setEmailContent("mock-email");
		emailTemplate.setEmailSubject("mock-subject");
		emailTemplate.setEmailTo("mock@mosip.io");
		when(templateUtil.getEmailTemplate(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(emailTemplate);
		String emailUrl = mosipEnvironment.getOtpSenderEmailApi();
		String emailResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getEmailRespo = ResponseEntity.ok(emailResp);
		when(authRestTemplate.exchange(Mockito.eq(emailUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getEmailRespo);
		List<String> channel = new ArrayList<>();
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		RequestWrapper<OtpUser> otpUserDto = new RequestWrapper<OtpUser>();
		otpUserDto.setRequest(otpUser);
		mockMvc.perform(post("/authenticate/sendotp").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(otpUserDto))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("SUCCESS")));
	}

	@Test
	public void sendOTPSMSTest() throws Exception {
		// is user already present
		Map<String, String> registerPathParams = new HashMap<>();
		registerPathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users?username=").concat("112211"));

		String userIDResp = "[\r\n" + "  {\r\n" + "    \"username\": \"112211\",\r\n" + "    \"id\": \"8282828282\"\r\n"
				+ "  }\r\n" + "]";
		when(keycloakRestTemplate.exchange(
				Mockito.eq(uriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));

		// register user

		UriComponentsBuilder registerUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users"));
		when(keycloakRestTemplate.exchange(
				Mockito.eq(registerUriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.POST), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok("{}"));

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder accessTokenuriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(
				Mockito.eq(accessTokenuriComponentsBuilder.buildAndExpand(pathParams).toUriString()), Mockito.any(),
				Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);

		final String url = mosipEnvironment.getGenerateOtpApi();
		String otpResponse = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"otp\": \"820121\",\r\n" + "    \"status\": \"SUCCESS\"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getOTPRespo = ResponseEntity.ok(otpResponse);
		when(authRestTemplate.postForEntity(Mockito.eq(url), Mockito.any(), Mockito.eq(String.class)))
				.thenReturn(getOTPRespo);
		// sms
		when(templateUtil.getOtpSmsMessage(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("MOCK_MESSAGE");
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		RequestWrapper<OtpUser> otpUserDto = new RequestWrapper<OtpUser>();
		otpUserDto.setRequest(otpUser);
		mockMvc.perform(post("/authenticate/sendotp").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(otpUserDto))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("SUCCESS")));
	}

	@Test
	public void sendOTPSMSEmailTest() throws Exception {
		// is user already present
		Map<String, String> registerPathParams = new HashMap<>();
		registerPathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users?username=").concat("112211"));

		String userIDResp = "[\r\n" + "  {\r\n" + "    \"username\": \"112211\",\r\n" + "    \"id\": \"8282828282\"\r\n"
				+ "  }\r\n" + "]";
		when(keycloakRestTemplate.exchange(
				Mockito.eq(uriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));

		// register user

		UriComponentsBuilder registerUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users"));
		when(keycloakRestTemplate.exchange(
				Mockito.eq(registerUriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.POST), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok("{}"));

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder accessTokenuriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(
				Mockito.eq(accessTokenuriComponentsBuilder.buildAndExpand(pathParams).toUriString()), Mockito.any(),
				Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);

		final String url = mosipEnvironment.getGenerateOtpApi();
		String otpResponse = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"otp\": \"820121\",\r\n" + "    \"status\": \"SUCCESS\"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getOTPRespo = ResponseEntity.ok(otpResponse);
		when(authRestTemplate.postForEntity(Mockito.eq(url), Mockito.any(), Mockito.eq(String.class)))
				.thenReturn(getOTPRespo);
		// sms
		when(templateUtil.getOtpSmsMessage(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("MOCK_MESSAGE");
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);

		// email and Template
		OTPEmailTemplate emailTemplate = new OTPEmailTemplate();
		emailTemplate.setEmailContent("mock-email");
		emailTemplate.setEmailSubject("mock-subject");
		emailTemplate.setEmailTo("mock@mosip.io");
		when(templateUtil.getEmailTemplate(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(emailTemplate);
		String emailUrl = mosipEnvironment.getOtpSenderEmailApi();
		String emailResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getEmailRespo = ResponseEntity.ok(emailResp);
		when(authRestTemplate.exchange(Mockito.eq(emailUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getEmailRespo);
		
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		RequestWrapper<OtpUser> otpUserDto = new RequestWrapper<OtpUser>();
		otpUserDto.setRequest(otpUser);
		mockMvc.perform(post("/authenticate/sendotp").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(otpUserDto))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("success")));
	}
	
	@Test
	public void sendOTPInvalidUserIDTest() throws Exception {
		// is user already present
		Map<String, String> registerPathParams = new HashMap<>();
		registerPathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users?username=").concat("112211"));

		String userIDResp = "[\r\n" + "  {\r\n" + "    \"username\": \"112211\",\r\n" + "    \"id\": \"8282828282\"\r\n"
				+ "  }\r\n" + "]";
		when(keycloakRestTemplate.exchange(
				Mockito.eq(uriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));

		// register user

		UriComponentsBuilder registerUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users"));
		when(keycloakRestTemplate.exchange(
				Mockito.eq(registerUriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.POST), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok("{}"));

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder accessTokenuriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(
				Mockito.eq(accessTokenuriComponentsBuilder.buildAndExpand(pathParams).toUriString()), Mockito.any(),
				Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);

		final String url = mosipEnvironment.getGenerateOtpApi();
		String otpResponse = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"otp\": \"820121\",\r\n" + "    \"status\": \"SUCCESS\"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getOTPRespo = ResponseEntity.ok(otpResponse);
		when(authRestTemplate.postForEntity(Mockito.eq(url), Mockito.any(), Mockito.eq(String.class)))
				.thenReturn(getOTPRespo);
		// sms
		when(templateUtil.getOtpSmsMessage(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("MOCK_MESSAGE");
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);

		// email and Template
		OTPEmailTemplate emailTemplate = new OTPEmailTemplate();
		emailTemplate.setEmailContent("mock-email");
		emailTemplate.setEmailSubject("mock-subject");
		emailTemplate.setEmailTo("mock@mosip.io");
		when(templateUtil.getEmailTemplate(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(emailTemplate);
		String emailUrl = mosipEnvironment.getOtpSenderEmailApi();
		String emailResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getEmailRespo = ResponseEntity.ok(emailResp);
		when(authRestTemplate.exchange(Mockito.eq(emailUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getEmailRespo);
		
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("Invalid");
		otpUser.setContext("USERID");
		RequestWrapper<OtpUser> otpUserDto = new RequestWrapper<OtpUser>();
		otpUserDto.setRequest(otpUser);
		mockMvc.perform(post("/authenticate/sendotp").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(otpUserDto))).andExpect(status().isOk())
				.andExpect(jsonPath("$.errors[0].errorCode", is("401")));
	}

	@Test
	public void userIdOTPUINTest() throws Exception {
		// is user already present
		Map<String, String> registerPathParams = new HashMap<>();
		registerPathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakBaseUrl.concat("/users?username=").concat("112211"));

		String userIDResp = "[\r\n" + "  {\r\n" + "    \"username\": \"112211\",\r\n" + "    \"id\": \"8282828282\"\r\n"
				+ "  }\r\n" + "]";
		when(keycloakRestTemplate.exchange(
				Mockito.eq(uriComponentsBuilder.buildAndExpand(registerPathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder tokenUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(
				Mockito.eq(tokenUriComponentsBuilder.buildAndExpand(pathParams).toUriString()), Mockito.any(),
				Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);

		// validateOTP
		String validateOTPUrl = mosipEnvironment.getVerifyOtpUserApi();
		UriComponentsBuilder validateOTPUrlBuilder = UriComponentsBuilder.fromHttpUrl(validateOTPUrl)
				.queryParam("key", "112211").queryParam("otp", "717171");
		ResponseWrapper<OtpValidatorResponseDto> repwr = new ResponseWrapper<>();
		OtpValidatorResponseDto otpValidatorResponseDto = new OtpValidatorResponseDto();
		otpValidatorResponseDto.setMessage("SUCCESS");
		otpValidatorResponseDto.setStatus("SUCCESS");
		repwr.setResponse(otpValidatorResponseDto);
		when(authRestTemplate.exchange(Mockito.eq(validateOTPUrlBuilder.toUriString()), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repwr)));

		// request
		RequestWrapper<UserOtp> userOtpDto = new RequestWrapper<UserOtp>();
		UserOtp userOtp = new UserOtp();
		userOtp.setAppId("ida");
		userOtp.setOtp("717171");
		userOtp.setUserId("112211");
		userOtpDto.setRequest(userOtp);

		mockMvc.perform(post("/authenticate/useridOTP").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userOtpDto))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("SUCCESS")));
	}
	
	

	@Test
	public void validateTokenTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		StringBuilder urlBuilder = new StringBuilder().append(keycloakBaseURL).append("/auth/realms/").append("mosip")
				.append("/protocol/openid-connect/userinfo");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString());
		when(authRestTemplate.exchange(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(""));

		Cookie cookie = new Cookie("Authorization",
				"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw");
		mockMvc.perform(get("/authorize/admin/validateToken").contentType(MediaType.APPLICATION_JSON).cookie(cookie))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.response.userId", is("service-account-mosip-resident-client")));
	}

	@Test
	public void validateTokenAuthenticationServiceExceptionTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		StringBuilder urlBuilder = new StringBuilder().append(keycloakBaseURL).append("/auth/realms/").append("mosip")
				.append("/protocol/openid-connect/userinfo");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString());
		String resp = "{\r\n" + "  \"error\": \"UNAUTHORIZED\",\r\n" + "  \"error_description\": \"UNAUTHORIZED\" }";

		when(authRestTemplate.exchange(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class)))
						.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", resp.getBytes(),
								Charset.defaultCharset()));

		Cookie cookie = new Cookie("Authorization",
				"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw");
		mockMvc.perform(get("/authorize/admin/validateToken").contentType(MediaType.APPLICATION_JSON).cookie(cookie))
				.andExpect(status().isInternalServerError());
	}
	
	@Test
	public void validateTokenAuthManagerExceptionTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		StringBuilder urlBuilder = new StringBuilder().append(keycloakBaseURL).append("/auth/realms/").append("mosip")
				.append("/protocol/openid-connect/userinfo");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString());
		String resp = "{\r\n" + "  \"error\": \"UNAUTHORIZED\",\r\n" + "  \"error_description\": \"UNAUTHORIZED\" }";

		when(authRestTemplate.exchange(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class)))
						.thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "404", resp.getBytes(),
								Charset.defaultCharset()));

		Cookie cookie = new Cookie("Authorization",
				"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw");
		mockMvc.perform(get("/authorize/admin/validateToken").contentType(MediaType.APPLICATION_JSON).cookie(cookie))
		.andExpect(status().isOk())
		.andExpect(jsonPath("$.errors[0].errorCode", is("KER-ATH-025")));
	}

	
	@Test
	public void validateTokenEmptyTokenTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		StringBuilder urlBuilder = new StringBuilder().append(keycloakBaseURL).append("/auth/realms/").append("mosip")
				.append("/protocol/openid-connect/userinfo");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString());
		String resp = "{\r\n" + "  \"error\": \"UNAUTHORIZED\",\r\n" + "  \"error_description\": \"UNAUTHORIZED\" }";

		when(authRestTemplate.exchange(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class)))
						.thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "404", resp.getBytes(),
								Charset.defaultCharset()));

		Cookie cookie = new Cookie("Authorization",
				"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw");
		mockMvc.perform(get("/authorize/admin/validateToken").contentType(MediaType.APPLICATION_JSON))
		.andExpect(status().isOk())
		.andExpect(jsonPath("$.errors[0].errorCode", is("KER-ATH-006")));
	}

	
	
	@Test
	public void validateTokenForbiddenExceptionTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		StringBuilder urlBuilder = new StringBuilder().append(keycloakBaseURL).append("/auth/realms/").append("mosip")
				.append("/protocol/openid-connect/userinfo");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString());
		String resp = "{\r\n" + "  \"error\": \"FORBIDDEN\",\r\n" + "  \"error_description\": \"FORBIDDEN\" }";

		when(authRestTemplate.exchange(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class)))
						.thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", resp.getBytes(),
								Charset.defaultCharset()));

		Cookie cookie = new Cookie("Authorization",
				"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw");
		mockMvc.perform(get("/authorize/admin/validateToken").contentType(MediaType.APPLICATION_JSON).cookie(cookie))
				.andExpect(status().isInternalServerError());
	}

	@Test
	public void logoutTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		String mockToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		StringBuilder urlBuilder = new StringBuilder().append("https://dev.mosip.net/keycloak/auth/realms/mosip")
				.append("/protocol/openid-connect/logout");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString())
				.queryParam(KeycloakConstants.ID_TOKEN_HINT, mockToken);

		when(authRestTemplate.getForEntity(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(String.class)))
				.thenReturn(ResponseEntity.ok(""));

		Cookie cookie = new Cookie("Authorization", mockToken);
		mockMvc.perform(delete("/logout/user").contentType(MediaType.APPLICATION_JSON).cookie(cookie))
				.andExpect(status().isOk()).andExpect(jsonPath("$.response.status", is("Success")));
	}
	
	@Test
	public void logoutEmptyTokenTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		String mockToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		StringBuilder urlBuilder = new StringBuilder().append("https://dev.mosip.net/keycloak/auth/realms/mosip")
				.append("/protocol/openid-connect/logout");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString())
				.queryParam(KeycloakConstants.ID_TOKEN_HINT, mockToken);

		when(authRestTemplate.getForEntity(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(String.class)))
				.thenReturn(ResponseEntity.ok(""));

		Cookie cookie = new Cookie("Authorization", mockToken);
		mockMvc.perform(delete("/logout/user").contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isInternalServerError()).andExpect(jsonPath("$.errors[0].errorCode", is("500")));
	}
	
	@Test
	public void logoutFailedTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		String mockToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		StringBuilder urlBuilder = new StringBuilder().append("https://dev.mosip.net/keycloak/auth/realms/mosip")
				.append("/protocol/openid-connect/logout");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString())
				.queryParam(KeycloakConstants.ID_TOKEN_HINT, mockToken);

		when(authRestTemplate.getForEntity(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(String.class)))
				.thenReturn(ResponseEntity.notFound().build());

		Cookie cookie = new Cookie("Authorization", mockToken);
		mockMvc.perform(delete("/logout/user").contentType(MediaType.APPLICATION_JSON).cookie(cookie))
				.andExpect(status().isOk()).andExpect(jsonPath("$.response.status", is("Failed")));
	}
	
	@Test
	public void logoutRestExceptionTest() throws Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<MosipUserDto>();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		responseWrapper.setResponse(mosipUserDto);

		String mockToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		StringBuilder urlBuilder = new StringBuilder().append("https://dev.mosip.net/keycloak/auth/realms/mosip")
				.append("/protocol/openid-connect/logout");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(urlBuilder.toString())
				.queryParam(KeycloakConstants.ID_TOKEN_HINT, mockToken);
		when(authRestTemplate.getForEntity(Mockito.eq(uriComponentsBuilder.toUriString()), Mockito.eq(String.class)))
		.thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "404","not found".getBytes(),
				Charset.defaultCharset()));

		Cookie cookie = new Cookie("Authorization", mockToken);
		mockMvc.perform(delete("/logout/user").contentType(MediaType.APPLICATION_JSON).cookie(cookie))
				.andExpect(status().isOk()).andExpect(jsonPath("$.errors[0].errorCode", is("KER-ATH-025")));
	}

	@Test
	public void authenticateUserTest() throws Exception {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		accessTokenResponse.setRefresh_expires_in("36000");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class)))
						.thenReturn(ResponseEntity.ok(accessTokenResponse));

		RequestWrapper<LoginUser> request = new RequestWrapper<LoginUser>();
		LoginUser loginUser = new LoginUser();
		loginUser.setAppId("ida");
		loginUser.setPassword("mockpass");
		loginUser.setUserName("mosckuser");
		request.setRequest(loginUser);

		mockMvc.perform(post("/authenticate/useridPwd").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(request))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("success")));
	}
	
	
	@Test
	public void authenticateUserUnAuthTest() throws Exception {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		accessTokenResponse.setRefresh_expires_in("36000");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class)))
		.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "invalid token".getBytes(),
				Charset.defaultCharset()));

		RequestWrapper<LoginUser> request = new RequestWrapper<LoginUser>();
		LoginUser loginUser = new LoginUser();
		loginUser.setAppId("ida");
		loginUser.setPassword("mockpass");
		loginUser.setUserName("mosckuser");
		request.setRequest(loginUser);

		mockMvc.perform(post("/authenticate/useridPwd").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(request))).andExpect(status().isOk())
				.andExpect(jsonPath("$.errors[0].errorCode", is("KER-ATH-023")));
	}
	
	

	@Test
	public void authenticateUserRequestValidationTest() throws Exception {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		accessTokenResponse.setRefresh_expires_in("36000");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class)))
		.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", "invalid request".getBytes(),
				Charset.defaultCharset()));

		RequestWrapper<LoginUser> request = new RequestWrapper<LoginUser>();
		LoginUser loginUser = new LoginUser();
		loginUser.setAppId("ida");
		loginUser.setPassword("mockpass");
		loginUser.setUserName("mosckuser");
		request.setRequest(loginUser);

		mockMvc.perform(post("/authenticate/useridPwd").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(request))).andExpect(status().isOk())
				.andExpect(jsonPath("$.errors[0].errorCode", is("KER-ATH-004")));
	}
	
	@Test
	public void authenticateUserServerErrorTest() throws Exception {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		accessTokenResponse.setRefresh_expires_in("36000");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class)))
		.thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "404", "not available".getBytes(),
				Charset.defaultCharset()));

		RequestWrapper<LoginUser> request = new RequestWrapper<LoginUser>();
		LoginUser loginUser = new LoginUser();
		loginUser.setAppId("ida");
		loginUser.setPassword("mockpass");
		loginUser.setUserName("mosckuser");
		request.setRequest(loginUser);

		mockMvc.perform(post("/authenticate/useridPwd").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(request))).andExpect(status().isOk())
				.andExpect(jsonPath("$.errors[0].errorCode", is("KER-ATH-500")));
	}


	@Test
	public void refreshTokenTest() throws Exception {

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		accessTokenResponse.setRefresh_expires_in("36000");
		Map<String, String> pathParams = new HashMap<>();

		pathParams.put(AuthConstant.REALM_ID, "mosip");

		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");

		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class)))
						.thenReturn(ResponseEntity.ok(accessTokenResponse));

		RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
		refreshTokenRequest.setClientID("ida");
		refreshTokenRequest.setClientSecret("secret");

		LoginUser loginUser = new LoginUser();
		loginUser.setAppId("ida");
		loginUser.setPassword("mockpass");
		loginUser.setUserName("mosckuser");
		Cookie cookie = new Cookie("refresh_token", "MOCK_REFRESH_TOKEN");
		mockMvc.perform(post("/authorize/refreshToken/ida").contentType(MediaType.APPLICATION_JSON).cookie(cookie)
				.content(objectMapper.writeValueAsString(loginUser))).andExpect(status().isOk())
				.andExpect(jsonPath("$.response.status", is("SUCCESS")));
	}
	
	@Test
	public void refreshTokenHttpClientErrorTest() throws Exception {

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		accessTokenResponse.setRefresh_expires_in("36000");
		Map<String, String> pathParams = new HashMap<>();

		pathParams.put(AuthConstant.REALM_ID, "mosip");

		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");

		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class)))
		.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", "bad Req".getBytes(),
				Charset.defaultCharset()));

		RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
		refreshTokenRequest.setClientID("ida");
		refreshTokenRequest.setClientSecret("secret");

		LoginUser loginUser = new LoginUser();
		loginUser.setAppId("ida");
		loginUser.setPassword("mockpass");
		loginUser.setUserName("mosckuser");
		Cookie cookie = new Cookie("refresh_token", "MOCK_REFRESH_TOKEN");
		mockMvc.perform(post("/authorize/refreshToken/ida").contentType(MediaType.APPLICATION_JSON).cookie(cookie)
				.content(objectMapper.writeValueAsString(loginUser))).andExpect(status().isInternalServerError())
				.andExpect(jsonPath("$.errors[0].errorCode", is("500")));
	}
}
