package io.mosip.kernel.auth.service.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultimpl.config.MosipEnvironment;
import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.dto.AccessTokenResponse;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpGenerateResponseDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpTemplateDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.OtpTemplateResponseDto;
import io.mosip.kernel.auth.defaultimpl.dto.otp.email.OTPEmailTemplate;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerServiceException;
import io.mosip.kernel.auth.defaultimpl.service.OTPGenerateService;
import io.mosip.kernel.auth.defaultimpl.service.OTPService;
import io.mosip.kernel.auth.defaultimpl.util.MemoryCache;
import io.mosip.kernel.auth.defaultimpl.util.OtpValidator;
import io.mosip.kernel.auth.defaultimpl.util.TemplateUtil;
import io.mosip.kernel.auth.test.AuthTestBootApplication;
import io.mosip.kernel.core.authmanager.exception.AuthNException;
import io.mosip.kernel.core.authmanager.exception.AuthZException;
import io.mosip.kernel.core.authmanager.model.AuthNResponseDto;
import io.mosip.kernel.core.authmanager.model.MosipUserDto;
import io.mosip.kernel.core.authmanager.model.OtpUser;
import io.mosip.kernel.core.http.ResponseWrapper;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class OtpServiceTest {
	
	@Autowired
	private OTPService oTPService;

	@Qualifier("authRestTemplate")
	@MockBean
	RestTemplate authRestTemplate;

	@Autowired
	MosipEnvironment mosipEnvironment;

	@MockBean
	OTPGenerateService oTPGenerateService;

	@Autowired
	private ObjectMapper mapper;

	@MockBean
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
	
	@Autowired
	private MemoryCache<String, AccessTokenResponse> memoryCache;
	
	@Test(expected = AuthNException.class)
	public void sendOTPForUinAuthNExceptionTest() throws Exception  {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-ATH-401\", \"message\": \"UNAUTHORIZED\" } ]\r\n" + "}";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", resp.getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTPForUin(mosipUserDto, otpUser, "mosip");
		
	}
	
	@Test(expected = AuthManagerException.class)
	public void sendOTPForUinAuthManagerExceptionUnAuthTest() throws Exception  {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "UNAUTHORIZED".getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTPForUin(mosipUserDto, otpUser, "mosip");
		
	}
	
	@Test(expected = AuthZException.class)
	public void sendOTPForUinAuthZExceptionTest() throws Exception  {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-ATH-403\", \"message\": \"Forbidden\" } ]\r\n" + "}";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", resp.getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTPForUin(mosipUserDto, otpUser, "mosip");
		
	}
	
	@Test(expected = AuthManagerException.class)
	public void sendOTPForUinAuthManagerExceptionForbiddenTest() throws Exception  {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "404", "access denied".getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTPForUin(mosipUserDto, otpUser, "mosip");
		
	}
	
	

	@Test(expected = AuthManagerServiceException.class)
	public void sendOTPForUinValidationErrorTest() throws Exception  {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-OTP-400\", \"message\": \"Bad Request\" } ]\r\n" + "}";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", resp.getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTPForUin(mosipUserDto, otpUser, "mosip");
		
	}
	
	@Test(expected = AuthManagerException.class)
	public void sendOTPForUinClientErrorTest() throws Exception  {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", "bad Req".getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTPForUin(mosipUserDto, otpUser, "mosip");	
	}
	
	
	@Test
	public void sendOTPForUinBlockedUserTest() throws Exception  {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		OtpGenerateResponseDto otpGenerateResponseDto = new OtpGenerateResponseDto();
		otpGenerateResponseDto.setStatus("USER_BLOCKED");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);
		when(oTPGenerateService.generateOTP(Mockito.any(),
				Mockito.any())).thenReturn(otpGenerateResponseDto);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		AuthNResponseDto authNResponseDto = oTPService.sendOTPForUin(mosipUserDto, otpUser, "mosip");	
		assertThat(authNResponseDto.getStatus(),is(AuthConstant.FAILURE_STATUS));
	}
	
	
	@Test(expected = AuthNException.class)
	public void sendOTPAuthNExceptionTest() throws Exception  {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-ATH-401\", \"message\": \"UNAUTHORIZED\" } ]\r\n" + "}";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", resp.getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTP(mosipUserDto, otpUser, "preregistration");
		
	}
	
	@Test(expected = AuthManagerException.class)
	public void sendOTPAuthManagerExceptionUnAuthTest() throws Exception  {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "UNAUTHORIZED".getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTP(mosipUserDto, otpUser, "preregistration");
		
	}
	
	@Test(expected = AuthZException.class)
	public void sendOTPAuthZExceptionTest() throws Exception  {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-ATH-403\", \"message\": \"Forbidden\" } ]\r\n" + "}";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", resp.getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTP(mosipUserDto, otpUser, "preregistration");
		
	}
	
	@Test(expected = AuthManagerException.class)
	public void sendOTPAuthManagerExceptionForbiddenTest() throws Exception  {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", "access denied".getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTP(mosipUserDto, otpUser, "preregistration");
		
	}
	
	

	@Test(expected = AuthManagerServiceException.class)
	public void sendOTPValidationErrorTest() throws Exception  {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-OTP-400\", \"message\": \"Bad Request\" } ]\r\n" + "}";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", resp.getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTP(mosipUserDto, otpUser, "preregistration");
		
	}
	
	@Test(expected = AuthManagerException.class)
	public void sendOTPClientErrorTest() throws Exception  {
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", "bad Req".getBytes(),
								Charset.defaultCharset()));
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		oTPService.sendOTP(mosipUserDto, otpUser, "preregistration");	
	}
	
	
	@Test
	public void sendOTPBlockedUserTest() throws Exception  {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "preregistration");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		OtpGenerateResponseDto otpGenerateResponseDto = new OtpGenerateResponseDto();
		otpGenerateResponseDto.setStatus("USER_BLOCKED");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);
		when(oTPGenerateService.generateOTP(Mockito.any(),
				Mockito.any())).thenReturn(otpGenerateResponseDto);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		AuthNResponseDto authNResponseDto = oTPService.sendOTP(mosipUserDto, otpUser, "preregistration");	
		assertThat(authNResponseDto.getStatus(),is(AuthConstant.FAILURE_STATUS));
	}

	@Test
	public void sendOTPEmailTest() throws Exception  {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		OtpGenerateResponseDto otpGenerateResponseDto = new OtpGenerateResponseDto();
		otpGenerateResponseDto.setOtp("110022");
		otpGenerateResponseDto.setStatus("Success");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);
		when(oTPGenerateService.generateOTP(Mockito.any(),
				Mockito.any())).thenReturn(otpGenerateResponseDto);
		
		//get otp email
		ResponseWrapper<OtpTemplateResponseDto> otpEmailresp = new ResponseWrapper<>();
		OtpTemplateResponseDto otpTemplateResponseDto = new OtpTemplateResponseDto();
		ArrayList<OtpTemplateDto> templates = new ArrayList<OtpTemplateDto>();
		OtpTemplateDto otpTemplateDto = new OtpTemplateDto();
		otpTemplateDto.setId("ida");
		otpTemplateDto.setFileText("your otp os $otp");
		templates.add(otpTemplateDto);
		otpTemplateResponseDto.setTemplates(templates);
		otpEmailresp.setResponse(otpTemplateResponseDto);
		final String url = mosipEnvironment.getMasterDataTemplateApi() + "/" + mosipEnvironment.getPrimaryLanguage()
		+ mosipEnvironment.getMasterDataOtpTemplate();
 when(authRestTemplate.exchange(Mockito.eq(url), Mockito.eq(HttpMethod.GET),Mockito.any(),
		Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(mapper.writeValueAsString(otpEmailresp)));
		
 
 //email
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
		
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		AuthNResponseDto authNResponseDto = oTPService.sendOTP(mosipUserDto, channel, "ida");	
		assertThat(authNResponseDto.getStatus(),is("SUCCESS"));
	}
	
	
	@Test
	public void sendOTPPhoneTest() throws Exception  {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		OtpGenerateResponseDto otpGenerateResponseDto = new OtpGenerateResponseDto();
		otpGenerateResponseDto.setOtp("110022");
		otpGenerateResponseDto.setStatus("Success");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(getAuthAccessTokenResponse);
		when(oTPGenerateService.generateOTP(Mockito.any(),
				Mockito.any())).thenReturn(otpGenerateResponseDto);
		
		
		ResponseWrapper<OtpTemplateResponseDto> otpEmailresp = new ResponseWrapper<>();
		OtpTemplateResponseDto otpTemplateResponseDto = new OtpTemplateResponseDto();
		ArrayList<OtpTemplateDto> templates = new ArrayList<OtpTemplateDto>();
		OtpTemplateDto otpTemplateDto = new OtpTemplateDto();
		otpTemplateDto.setId("ida");
		otpTemplateDto.setFileText("your otp os $otp");
		templates.add(otpTemplateDto);
		otpTemplateResponseDto.setTemplates(templates);
		otpEmailresp.setResponse(otpTemplateResponseDto);
		final String url = mosipEnvironment.getMasterDataTemplateApi() + "/" + mosipEnvironment.getPrimaryLanguage()
		+ mosipEnvironment.getMasterDataOtpTemplate();
 when(authRestTemplate.exchange(Mockito.eq(url), Mockito.eq(HttpMethod.GET),Mockito.any(),
		Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(mapper.writeValueAsString(otpEmailresp)));
		
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		AuthNResponseDto authNResponseDto = oTPService.sendOTP(mosipUserDto, channel, "ida");	
		assertThat(authNResponseDto.getStatus(),is("SUCCESS"));
	}
	
	
	@Test(expected = AuthNException.class)
	public void sendOTPPhoneUnAuthErrorTest() throws Exception  {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-OTP-401\", \"message\": \"Bad Request\" } ]\r\n" + "}";

		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		OtpGenerateResponseDto otpGenerateResponseDto = new OtpGenerateResponseDto();
		otpGenerateResponseDto.setOtp("110022");
		otpGenerateResponseDto.setStatus("Success");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", resp.getBytes(),
						Charset.defaultCharset()));
		when(oTPGenerateService.generateOTP(Mockito.any(),
				Mockito.any())).thenReturn(otpGenerateResponseDto);
		
		
		ResponseWrapper<OtpTemplateResponseDto> otpEmailresp = new ResponseWrapper<>();
		OtpTemplateResponseDto otpTemplateResponseDto = new OtpTemplateResponseDto();
		ArrayList<OtpTemplateDto> templates = new ArrayList<OtpTemplateDto>();
		OtpTemplateDto otpTemplateDto = new OtpTemplateDto();
		otpTemplateDto.setId("ida");
		otpTemplateDto.setFileText("your otp os $otp");
		templates.add(otpTemplateDto);
		otpTemplateResponseDto.setTemplates(templates);
		otpEmailresp.setResponse(otpTemplateResponseDto);
		final String url = mosipEnvironment.getMasterDataTemplateApi() + "/" + mosipEnvironment.getPrimaryLanguage()
		+ mosipEnvironment.getMasterDataOtpTemplate();
 when(authRestTemplate.exchange(Mockito.eq(url), Mockito.eq(HttpMethod.GET),Mockito.any(),
		Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(mapper.writeValueAsString(otpEmailresp)));
		
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		AuthNResponseDto authNResponseDto = oTPService.sendOTP(mosipUserDto, channel, "ida");	
		assertThat(authNResponseDto.getStatus(),is("SUCCESS"));
	}
	
	
	@Test(expected = AuthZException.class)
	public void sendOTPPhoneForbiddenErrorTest() throws Exception  {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-OTP-401\", \"message\": \"Bad Request\" } ]\r\n" + "}";

		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		OtpGenerateResponseDto otpGenerateResponseDto = new OtpGenerateResponseDto();
		otpGenerateResponseDto.setOtp("110022");
		otpGenerateResponseDto.setStatus("Success");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", resp.getBytes(),
						Charset.defaultCharset()));
		when(oTPGenerateService.generateOTP(Mockito.any(),
				Mockito.any())).thenReturn(otpGenerateResponseDto);
		
		
		ResponseWrapper<OtpTemplateResponseDto> otpEmailresp = new ResponseWrapper<>();
		OtpTemplateResponseDto otpTemplateResponseDto = new OtpTemplateResponseDto();
		ArrayList<OtpTemplateDto> templates = new ArrayList<OtpTemplateDto>();
		OtpTemplateDto otpTemplateDto = new OtpTemplateDto();
		otpTemplateDto.setId("ida");
		otpTemplateDto.setFileText("your otp os $otp");
		templates.add(otpTemplateDto);
		otpTemplateResponseDto.setTemplates(templates);
		otpEmailresp.setResponse(otpTemplateResponseDto);
		final String url = mosipEnvironment.getMasterDataTemplateApi() + "/" + mosipEnvironment.getPrimaryLanguage()
		+ mosipEnvironment.getMasterDataOtpTemplate();
 when(authRestTemplate.exchange(Mockito.eq(url), Mockito.eq(HttpMethod.GET),Mockito.any(),
		Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(mapper.writeValueAsString(otpEmailresp)));
		
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		AuthNResponseDto authNResponseDto = oTPService.sendOTP(mosipUserDto, channel, "ida");	
		assertThat(authNResponseDto.getStatus(),is("SUCCESS"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void sendOTPPhoneUnAuthAuthManagerExceptionErrorTest() throws Exception  {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-OTP-401\", \"message\": \"Bad Request\" } ]\r\n" + "}";

		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		OtpGenerateResponseDto otpGenerateResponseDto = new OtpGenerateResponseDto();
		otpGenerateResponseDto.setOtp("110022");
		otpGenerateResponseDto.setStatus("Success");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "unauth".getBytes(),
						Charset.defaultCharset()));
		when(oTPGenerateService.generateOTP(Mockito.any(),
				Mockito.any())).thenReturn(otpGenerateResponseDto);
		
		
		ResponseWrapper<OtpTemplateResponseDto> otpEmailresp = new ResponseWrapper<>();
		OtpTemplateResponseDto otpTemplateResponseDto = new OtpTemplateResponseDto();
		ArrayList<OtpTemplateDto> templates = new ArrayList<OtpTemplateDto>();
		OtpTemplateDto otpTemplateDto = new OtpTemplateDto();
		otpTemplateDto.setId("ida");
		otpTemplateDto.setFileText("your otp os $otp");
		templates.add(otpTemplateDto);
		otpTemplateResponseDto.setTemplates(templates);
		otpEmailresp.setResponse(otpTemplateResponseDto);
		final String url = mosipEnvironment.getMasterDataTemplateApi() + "/" + mosipEnvironment.getPrimaryLanguage()
		+ mosipEnvironment.getMasterDataOtpTemplate();
 when(authRestTemplate.exchange(Mockito.eq(url), Mockito.eq(HttpMethod.GET),Mockito.any(),
		Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(mapper.writeValueAsString(otpEmailresp)));
		
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		AuthNResponseDto authNResponseDto = oTPService.sendOTP(mosipUserDto, channel, "ida");	
		assertThat(authNResponseDto.getStatus(),is("SUCCESS"));
	}
	
	
	@Test(expected = AuthManagerException.class)
	public void sendOTPPhoneForbiddenAuthManagerExceptionrrorTest() throws Exception  {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("MOCK-ACCESS-TOKEN");
		accessTokenResponse.setRefresh_token("MOCK-REFRESH-TOKEN");
		accessTokenResponse.setExpires_in("3600");
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n" + "  \"errors\": [{ \"errorCode\": \"KER-OTP-401\", \"message\": \"Bad Request\" } ]\r\n" + "}";

		ResponseEntity<AccessTokenResponse> getAuthAccessTokenResponse = ResponseEntity.ok(accessTokenResponse);
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		OtpGenerateResponseDto otpGenerateResponseDto = new OtpGenerateResponseDto();
		otpGenerateResponseDto.setOtp("110022");
		otpGenerateResponseDto.setStatus("Success");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", "forbidden".getBytes(),
						Charset.defaultCharset()));
		when(oTPGenerateService.generateOTP(Mockito.any(),
				Mockito.any())).thenReturn(otpGenerateResponseDto);
		
		
		ResponseWrapper<OtpTemplateResponseDto> otpEmailresp = new ResponseWrapper<>();
		OtpTemplateResponseDto otpTemplateResponseDto = new OtpTemplateResponseDto();
		ArrayList<OtpTemplateDto> templates = new ArrayList<OtpTemplateDto>();
		OtpTemplateDto otpTemplateDto = new OtpTemplateDto();
		otpTemplateDto.setId("ida");
		otpTemplateDto.setFileText("your otp os $otp");
		templates.add(otpTemplateDto);
		otpTemplateResponseDto.setTemplates(templates);
		otpEmailresp.setResponse(otpTemplateResponseDto);
		final String url = mosipEnvironment.getMasterDataTemplateApi() + "/" + mosipEnvironment.getPrimaryLanguage()
		+ mosipEnvironment.getMasterDataOtpTemplate();
 when(authRestTemplate.exchange(Mockito.eq(url), Mockito.eq(HttpMethod.GET),Mockito.any(),
		Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(mapper.writeValueAsString(otpEmailresp)));
		
		String smsUrl = mosipEnvironment.getOtpSenderSmsApi();
		String smsResp = "{\r\n" + "  \"id\": \"string\",\r\n" + "  \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T20:23:08.027Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": {\r\n" + "    \"status\": \"SUCCESS\",\r\n" + "    \"message\": \"SUCCESS \"\r\n"
				+ "  },\r\n" + "  \"errors\": [\r\n" + "  ]\r\n" + "}";
		ResponseEntity<String> getSMSRespo = ResponseEntity.ok(smsResp);
		when(authRestTemplate.exchange(Mockito.eq(smsUrl), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(getSMSRespo);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setName("112211");
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("112211");
		otpUser.setAppId("ida");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("UIN");
		otpUser.setContext("uin");
		AuthNResponseDto authNResponseDto = oTPService.sendOTP(mosipUserDto, channel, "ida");	
		assertThat(authNResponseDto.getStatus(),is("SUCCESS"));
	}
	
	
}


