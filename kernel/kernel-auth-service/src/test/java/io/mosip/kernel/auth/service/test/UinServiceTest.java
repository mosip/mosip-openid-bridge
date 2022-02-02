package io.mosip.kernel.auth.service.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultimpl.config.MosipEnvironment;
import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.dto.otp.idrepo.ResponseDTO;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerServiceException;
import io.mosip.kernel.auth.defaultimpl.service.TokenGenerationService;
import io.mosip.kernel.auth.defaultimpl.service.UinService;
import io.mosip.kernel.auth.test.AuthTestBootApplication;
import io.mosip.kernel.core.authmanager.exception.AuthNException;
import io.mosip.kernel.core.authmanager.exception.AuthZException;
import io.mosip.kernel.core.authmanager.model.MosipUserDto;
import io.mosip.kernel.core.authmanager.model.OtpUser;
import io.mosip.kernel.core.http.ResponseWrapper;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class UinServiceTest {

	@Qualifier("authRestTemplate")
	@MockBean
	private RestTemplate authRestTemplate;

	@Autowired
	MosipEnvironment mosipEnvironment;

	@Autowired
	Environment en;

	@Autowired
	private ObjectMapper objectMapper;

	@MockBean
	private TokenGenerationService tokenService;

	@Autowired
	private UinService uinService;

	@Test
	public void getDetailsForValidateOtpTest() throws Exception {
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));
		MosipUserDto nus = uinService.getDetailsForValidateOtp("8202098910");
		assertThat(nus.getUserId(), is("8202098910"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getDetailsForValidateOtpTokenExceptionTest() throws Exception {
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenThrow(new Exception("user not found"));
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));
		uinService.getDetailsForValidateOtp("8202098910");
	}
	
	@Test(expected = AuthManagerException.class)
	public void getDetailsForValidateOtpUinDetailExceptionTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"IDR-IDS-002\", \"message\": \"user not found\" } ]\r\n" + "}";
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		MosipUserDto nus = uinService.getDetailsForValidateOtp("8202098910");
		assertThat(nus.getUserId(), is("8202098910"));
	}
	
	@Test(expected = AuthManagerServiceException.class)
	public void getDetailsForValidateValidationErrorsExceptionTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"IDR-IDS-001\", \"message\": \"user not found\" } ]\r\n" + "}";
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		MosipUserDto nus = uinService.getDetailsForValidateOtp("8202098910");
		assertThat(nus.getUserId(), is("8202098910"));
	}
	

	@Test(expected = AuthNException.class)
	public void getDetailsForValidateOtpAuthNExceptionTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"KER-ATH-401\", \"message\": \"UNAUTHORIZED\" } ]\r\n" + "}";
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", resp.getBytes(),
						Charset.defaultCharset()));
		uinService.getDetailsForValidateOtp("8202098910");

	}
	
	@Test(expected = BadCredentialsException.class)
	public void getDetailsForValidateOtpAuthManagerExceptionUnAuthTest() throws Exception {
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "UNAUTHORIZED".getBytes(),
						Charset.defaultCharset()));
		uinService.getDetailsForValidateOtp("8202098910");

	}

	@Test(expected = AuthZException.class)
	public void getDetailsForValidateOtpAuthZExceptionTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"KER-ATH-403\", \"message\": \"Forbidden\" } ]\r\n" + "}";
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", resp.getBytes(),
						Charset.defaultCharset()));
		uinService.getDetailsForValidateOtp("8202098910");

	}

	@Test(expected = AccessDeniedException.class)
	public void getDetailsForValidateOtpAuthManagerExceptionForbiddenTest() throws Exception {
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", "access denied".getBytes(),
						Charset.defaultCharset()));
		uinService.getDetailsForValidateOtp("8202098910");
		

	}

	@Test(expected = AuthManagerServiceException.class)
	public void getDetailsForValidateOtpValidationErrorTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"KER-OTP-400\", \"message\": \"Bad Request\" } ]\r\n" + "}";
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", resp.getBytes(),
						Charset.defaultCharset()));
		uinService.getDetailsForValidateOtp("8202098910");
	}

	@Test(expected = AuthManagerException.class)
	public void getDetailsForValidateOtpClientErrorTest() throws Exception {
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", "bad Req".getBytes(),
						Charset.defaultCharset()));
		uinService.getDetailsForValidateOtp("8202098910");
	}
	
	
	
	/////
	
	
	
	@Test(expected = AuthManagerException.class)
	public void getDetailsFromUinTokenExceptionTest() throws Exception {
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenThrow(new Exception("user not found"));
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		uinService.getDetailsFromUin(otpUser);
	}
		
	@Test(expected = AuthManagerServiceException.class)
	public void getDetailsFromUinValidationErrorsExceptionTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"IDR-IDS-001\", \"message\": \"user not found\" } ]\r\n" + "}";
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		uinService.getDetailsFromUin(otpUser);
	}
	

	@Test(expected = AuthNException.class)
	public void getDetailsFromUinAuthNExceptionTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"KER-ATH-401\", \"message\": \"UNAUTHORIZED\" } ]\r\n" + "}";
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", resp.getBytes(),
						Charset.defaultCharset()));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		uinService.getDetailsFromUin(otpUser);

	}
	
	@Test(expected = BadCredentialsException.class)
	public void getDetailsFromUinAuthManagerExceptionUnAuthTest() throws Exception {
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "UNAUTHORIZED".getBytes(),
						Charset.defaultCharset()));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		uinService.getDetailsFromUin(otpUser);

	}

	@Test(expected = AuthZException.class)
	public void getDetailsFromUinAuthZExceptionTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"KER-ATH-403\", \"message\": \"Forbidden\" } ]\r\n" + "}";
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", resp.getBytes(),
						Charset.defaultCharset()));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		uinService.getDetailsFromUin(otpUser);

	}

	@Test(expected = AccessDeniedException.class)
	public void getDetailsFromUinAuthManagerExceptionForbiddenTest() throws Exception {
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", "access denied".getBytes(),
						Charset.defaultCharset()));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		uinService.getDetailsFromUin(otpUser);
		

	}

	@Test(expected = AuthManagerServiceException.class)
	public void getDetailsFromUinValidationErrorTest() throws Exception {
		String resp = "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n"
				+ "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" + "  \"metadata\": {},\r\n"
				+ "  \"response\": { },\r\n"
				+ "  \"errors\": [{ \"errorCode\": \"KER-OTP-400\", \"message\": \"Bad Request\" } ]\r\n" + "}";
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", resp.getBytes(),
						Charset.defaultCharset()));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		uinService.getDetailsFromUin(otpUser);
	}
	@Test(expected = AuthManagerException.class)
	public void getDetailsFromUinClientErrorTest() throws Exception {
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", "bad Req".getBytes(),
						Charset.defaultCharset()));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		uinService.getDetailsFromUin(otpUser);
	}
	
	
	
	@Test(expected = AuthManagerException.class)
	public void getDetailsForValidateOtpRegistrationTest() throws Exception {
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		MosipUserDto nus = uinService.getDetailsFromUin(otpUser);
		
		assertThat(nus.getUserId(), is("8202098910"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getDetailsForValidateOtpEmailRegistrationTest() throws Exception {
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("phone", "8287382923");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		MosipUserDto nus = uinService.getDetailsFromUin(otpUser);
		
		assertThat(nus.getUserId(), is("8202098910"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getDetailsForValidateOtpPhoneRegistrationTest() throws Exception {
		// getDetailsForValidateOtp
		Map<String, String> uinValidateParams = new HashMap<String, String>();
		uinValidateParams.put(AuthConstant.APPTYPE_UIN.toLowerCase(), "8202098910");
		String uinValidateUrl = UriComponentsBuilder.fromHttpUrl(mosipEnvironment.getUinGetDetailsUrl())
				.buildAndExpand(uinValidateParams).toUriString();
		ResponseWrapper<ResponseDTO> repw = new ResponseWrapper<>();
		ResponseDTO uinResDTO = new ResponseDTO();
		Map<String, String> res = new LinkedHashMap<String, String>();
		res.put("email", "mock@mosip.io");
		uinResDTO.setIdentity(res);
		repw.setResponse(uinResDTO);

		when(tokenService.getUINBasedToken()).thenReturn("MOCK-TOKEN");
		when(authRestTemplate.exchange(Mockito.eq(uinValidateUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(objectMapper.writeValueAsString(repw)));
		List<String> channel = new ArrayList<>();
		channel.add("phone");
		channel.add("email");
		OtpUser otpUser = new OtpUser();
		otpUser.setUserId("8202098910");
		otpUser.setAppId("prereg");
		otpUser.setOtpChannel(channel);
		otpUser.setUseridtype("USERID");
		otpUser.setContext("USERID");
		MosipUserDto nus = uinService.getDetailsFromUin(otpUser);
		
		assertThat(nus.getUserId(), is("8202098910"));
	}
}
