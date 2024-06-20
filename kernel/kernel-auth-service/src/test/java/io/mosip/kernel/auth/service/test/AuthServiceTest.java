package io.mosip.kernel.auth.service.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.mosip.kernel.auth.defaultimpl.constant.AuthErrorCode;
import io.mosip.kernel.auth.defaultimpl.dto.KeycloakErrorResponseDto;
import io.mosip.kernel.auth.defaultimpl.service.impl.AuthServiceImpl;
import io.mosip.kernel.auth.defaultimpl.util.AuthUtil;
import io.mosip.kernel.core.authmanager.model.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.dto.AccessTokenResponse;
import io.mosip.kernel.auth.defaultimpl.dto.AuthToken;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultimpl.repository.impl.KeycloakImpl;
import io.mosip.kernel.auth.defaultimpl.service.OTPService;
import io.mosip.kernel.auth.defaultimpl.service.TokenService;
import io.mosip.kernel.auth.defaultimpl.service.UinService;
import io.mosip.kernel.auth.defaultimpl.util.TokenValidator;


@RunWith(MockitoJUnitRunner.class)
@AutoConfigureMockMvc
public class AuthServiceTest {
	@Value("${mosip.iam.open-id-url}")
	private String keycloakOpenIdUrl;


	@Mock
	KeycloakImpl keycloakImpl;


	@Mock
	TokenValidator tokenValidator;

	@Mock
	TokenService customTokenServices;

	@Mock
	OTPService oTPService;

	@Mock
	UinService uinService;

	@Qualifier("authRestTemplate")
	@Mock
	RestTemplate authRestTemplate;

	@Qualifier(value = "keycloakRestTemplate")
	@Mock
	private RestTemplate keycloakRestTemplate;

	@Mock
	AuthUtil authUtil;

	@Autowired
	private MockMvc mockMvc;

	@Mock
	private ObjectMapper objectMapper;

	@InjectMocks
	private AuthServiceImpl authService;

	@Test(expected = AuthManagerException.class)
	public void authenticateUserWithOTPValidationErrorTest() throws Exception {
		when(keycloakImpl.isUserAlreadyPresent(Mockito.any(), Mockito.any())).thenReturn(false);
		when(uinService.getDetailsForValidateOtp(Mockito.any())).thenReturn(null);
		UserOtp userOtp = new UserOtp();
		userOtp.setAppId("ida");
		userOtp.setUserId("112211");
		userOtp.setOtp("112211");
		authService.authenticateUserWithOtp(userOtp);
	}

	@Test
	public void authenticateUserWithOTPMosipTokenTest() throws Exception {
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		MosipUserTokenDto mosipToken = new MosipUserTokenDto();
		mosipToken.setMosipUserDto(mosipUserDto);
		mosipToken.setToken("mock-token");
		mosipToken.setRefreshToken("mock-token");
		mosipToken.setExpTime(3600);
		mosipToken.setRefreshExpTime(3600);
		mosipToken.setStatus("success");
		when(keycloakImpl.isUserAlreadyPresent(Mockito.any(), Mockito.any())).thenReturn(false);
		when(uinService.getDetailsForValidateOtp(Mockito.any())).thenReturn(mosipUserDto);
		when(oTPService.validateOTP(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(mosipToken);
		UserOtp userOtp = new UserOtp();
		userOtp.setAppId("ida");
		userOtp.setUserId("112211");
		userOtp.setOtp("112211");
		AuthNResponseDto authNResponseDto = authService.authenticateUserWithOtp(userOtp);
		assertThat(authNResponseDto.getStatus(), is("success"));
	}

	@Test
	public void invalidTokenTest() throws Exception {
		// token service ready mocked in mock bean
		AuthNResponse authNResponse = authService.invalidateToken("mock-token");
		assertThat(authNResponse.getStatus(), is("success"));
	}

	@Test
	public void getAllRolesTest() throws Exception {
		RolesListDto rolesListDto = new RolesListDto();
		Role role = new Role();
		role.setRoleId("123");
		role.setRoleName("processor");
		List<Role> roles = new ArrayList<>();
		roles.add(role);
		rolesListDto.setRoles(roles);
		when(keycloakImpl.getAllRoles(Mockito.any())).thenReturn(rolesListDto);
		RolesListDto rld = authService.getAllRoles("ida");
		assertThat(rld.getRoles().get(0).getRoleId(), is("123"));
	}

	@Test
	public void getListOfUsersDetailsTest() throws Exception {
		MosipUserListDto mosipUserListDto = new MosipUserListDto();
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		List<MosipUserDto> list = new ArrayList<>();
		list.add(mosipUserDto);
		mosipUserListDto.setMosipUserDtoList(list);
		when(keycloakImpl.getListOfUsersDetails(Mockito.any(),Mockito.any())).thenReturn(mosipUserListDto);
		List<String> userd = new ArrayList<>();
		userd.add("userdetails1");
		MosipUserListDto rld= authService.getListOfUsersDetails(userd,"ida");
		assertThat(rld.getMosipUserDtoList().get(0).getUserId(),is("mock-user"));
	}
	
	@Test
	public void getAllUserDetailsWithSaltTest() throws Exception {
		MosipUserSaltListDto mosipUserListDto = new MosipUserSaltListDto();
		MosipUserSalt mosipUserDto = new MosipUserSalt();
		mosipUserDto.setUserId("mock-user");
		List<MosipUserSalt> list = new ArrayList<>();
		list.add(mosipUserDto);
		mosipUserListDto.setMosipUserSaltList(list);
		when(keycloakImpl.getAllUserDetailsWithSalt(Mockito.any(),Mockito.any())).thenReturn(mosipUserListDto);
		List<String> userd = new ArrayList<>();
		userd.add("userdetails1");
		MosipUserSaltListDto rld= authService.getAllUserDetailsWithSalt(userd,"ida");
		assertThat(rld.getMosipUserSaltList().get(0).getUserId(),is("mock-user"));
	}
	

	
	@Test
	public void getKeycloakURITest() throws Exception {
		String authorizationEndpoint="http://localhost:8080/auth/realms/mosip/protocol/openid-connect/auth";
		ReflectionTestUtils.setField(authService, "authorizationEndpoint", authorizationEndpoint);
		String uri=authService.getKeycloakURI("mock-redirect-uri","mock-state");
		assertThat(uri,isA(String.class));
	}

	
	@Test
	public void validateTokenTest() throws Exception {
		MosipUserTokenDto mosipUserTokenDto = new MosipUserTokenDto();
		mosipUserTokenDto.setToken("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw");
		mosipUserTokenDto.setExpTime(3000);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		mosipUserTokenDto.setMosipUserDto(mosipUserDto);	
		AuthToken authToken = new AuthToken("mock-user", "mock-token", 3000, null);
		when(tokenValidator.validateToken(Mockito.anyString())).thenReturn(mosipUserTokenDto);
		when(customTokenServices.getTokenDetails(Mockito.anyString())).thenReturn(authToken);
		MosipUserTokenDto dto=authService.validateToken("mock-token");
		assertThat(dto.getMosipUserDto().getUserId(),is(mosipUserDto.getUserId()));
	}
	
	@Test(expected = AuthManagerException.class)
	public void validateTokenAuthManagerExceptionTest() throws Exception {
		MosipUserTokenDto mosipUserTokenDto = new MosipUserTokenDto();
		mosipUserTokenDto.setToken("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw");
		mosipUserTokenDto.setExpTime(3000);
		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setUserId("mock-user");
		mosipUserDto.setMail("mock-user@mosip.io");
		mosipUserDto.setMobile("9999999999");
		mosipUserDto.setRole("MOCK-ROLE");
		mosipUserTokenDto.setMosipUserDto(mosipUserDto);	
		AuthToken authToken = new AuthToken("mock-user", "mock-token", 3000, null);
		when(tokenValidator.validateToken(Mockito.anyString())).thenReturn(mosipUserTokenDto);
		when(customTokenServices.getTokenDetails(Mockito.anyString())).thenReturn(null);
		MosipUserTokenDto dto=authService.validateToken("mock-token");
		assertThat(dto.getMosipUserDto().getUserId(),is(mosipUserDto.getUserId()));
	}
	
	
	@Test
	public void authenticateUserwithClientIDTest() throws Exception {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");
		accessTokenResponse.setRefresh_expires_in("111");
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(ResponseEntity.ok(accessTokenResponse));
		LoginUserWithClientId loginUserWithClientId = new LoginUserWithClientId();
		loginUserWithClientId.setAppId("ida");
		loginUserWithClientId.setClientId("ida-client");
		loginUserWithClientId.setClientSecret("client-secret");
		loginUserWithClientId.setUserName("mock-user");
		loginUserWithClientId.setPassword("mock-pass");
		AuthNResponseDto authNResponseDto= authService.authenticateUser(loginUserWithClientId);
		assertThat(authNResponseDto.getStatus(),is(AuthConstant.SUCCESS_STATUS));
	}
	
	@Test(expected = AuthManagerException.class)
	public void authenticateUserwithClientIDUnAuthTest() throws Exception {
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");
		accessTokenResponse.setRefresh_expires_in("111");
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "not auth".getBytes(),
						Charset.defaultCharset()));
		LoginUserWithClientId loginUserWithClientId = new LoginUserWithClientId();
		loginUserWithClientId.setAppId("ida");
		loginUserWithClientId.setClientId("ida-client");
		loginUserWithClientId.setClientSecret("client-secret");
		loginUserWithClientId.setUserName("mock-user");
		loginUserWithClientId.setPassword("mock-pass");
		AuthNResponseDto authNResponseDto= authService.authenticateUser(loginUserWithClientId);
		assertThat(authNResponseDto.getStatus(),is(AuthConstant.SUCCESS_STATUS));
	}

	@Test
	public void authenticateUserWithValidUsernameTest() throws Exception {

		LoginUser loginUser=new LoginUser();
		loginUser.setUserName("mock-user");
		loginUser.setPassword("mock-pass");
		loginUser.setAppId("ida");

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");
		accessTokenResponse.setRefresh_expires_in("111");
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(ResponseEntity.ok(accessTokenResponse));

		AuthNResponseDto authNResponseDto=authService.authenticateUser(loginUser);
		assertThat(authNResponseDto.getStatus(),is(AuthConstant.SUCCESS_STATUS));
	}

	@Test
	public void authenticateUserWithInValidUsername_thenFail() throws Exception {

		LoginUser loginUser=new LoginUser();
		loginUser.setUserName("mock-user");
		loginUser.setPassword("mock-pass");
		loginUser.setAppId("ida");

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");
		accessTokenResponse.setRefresh_expires_in("111");
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "not auth".getBytes(),
				Charset.defaultCharset()));
		try{
			authService.authenticateUser(loginUser);
		}catch (AuthManagerException e){
			assertThat(e.getErrorCode(),is(AuthErrorCode.INVALID_CREDENTIALS.getErrorCode()));
		}
	}

	@Test
	public void authenticateUserWithBadRequest_thenFail() throws Exception {

		LoginUser loginUser = new LoginUser();
		loginUser.setUserName("mock-user");
		loginUser.setPassword("mock-pass");
		loginUser.setAppId("ida");

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");
		accessTokenResponse.setRefresh_expires_in("111");
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "400", "not auth".getBytes(),
				Charset.defaultCharset()));
		try {
			authService.authenticateUser(loginUser);
		} catch (AuthManagerException e) {
			assertThat(e.getErrorCode(), is(AuthErrorCode.REQUEST_VALIDATION_ERROR.getErrorCode()));
		}
	}

	@Test
	public void authenticateUserWithInvalidResponse_thenFail() throws Exception {

		LoginUser loginUser = new LoginUser();
		loginUser.setUserName("mock-user");
		loginUser.setPassword("mock-pass");
		loginUser.setAppId("ida");

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(ResponseEntity.ok(null));
		try {
			authService.authenticateUser(loginUser);
		} catch (AuthManagerException e) {
			assertThat(e.getErrorCode(), is(AuthErrorCode.CLIENT_ERROR.getErrorCode()));
		}
	}


	@Test
	public void authenticateWithOtpWithInValidIdTypeDetails_thenFail() throws Exception {

		OtpUser otpUser =new OtpUser();
		otpUser.setAppId("ida");
		List otpChannel = new ArrayList();
		otpChannel.add("MOBILE");
		otpUser.setOtpChannel(otpChannel);
		otpUser.setUserId("mock-user");

		try {
			authService.authenticateWithOtp(otpUser);
		}catch (AuthManagerException e){
			assertThat(e.getMessage(),is("Invalid User Id type"));
		}

	}

	@Test
	public void authenticateWithSecretKeyWithValidDetatils_thenPass() throws Exception {

		//AuthUtil authUtilMock = mock(AuthUtil.class);
		//RestTemplate restTemplate = mock(RestTemplate.class);

		ClientSecret clientSecret = new ClientSecret();
		clientSecret.setSecretKey("mock-secret");
		clientSecret.setAppId("prereg");
		clientSecret.setClientId("mock-client-id");

		when(authUtil.getRealmIdFromAppId(Mockito.any())).thenReturn("mosip");

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");
		accessTokenResponse.setRefresh_expires_in("111");

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(ResponseEntity.ok(accessTokenResponse));



		authService.authenticateWithSecretKey(clientSecret);
	}

	@Test
	public void authenticateWithSecretKeyWithInValidDetatils_thenPass() throws Exception {
		ClientSecret clientSecret = new ClientSecret();
		clientSecret.setSecretKey("mock-secret");
		clientSecret.setAppId("prereg");
		clientSecret.setClientId("mock-client-id");


		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");
		accessTokenResponse.setRefresh_expires_in("111");

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(ResponseEntity.ok(null));

		//when(authUtil.getRealmIdFromAppId(Mockito.any())).thenReturn("mosip");

		try{
			authService.authenticateWithSecretKey(clientSecret);
		}catch (AuthManagerException e){
			assertThat(e.getErrorCode(),is(AuthErrorCode.CLIENT_ERROR.getErrorCode()));
		}

	}

	@Test
	public void logoutUser_ValidDetails_thenPass(){

		AuthResponseDto authResponseDto=new AuthResponseDto();
		authResponseDto.setStatus("Success");

		when(tokenValidator.getissuer(Mockito.anyString())).thenReturn("issuer-mock");
		ResponseEntity<String> mockResponse = new ResponseEntity<>("mockResponse", HttpStatus.OK);
		Mockito.when(authRestTemplate.getForEntity(
						ArgumentMatchers.anyString(),
						ArgumentMatchers.<Class<String>>any()))
				.thenReturn(mockResponse);
		AuthResponseDto authResponseDtoResponse=authService.logoutUser("mock-token");
		assertThat(authResponseDtoResponse.getStatus(),is(authResponseDto.getStatus()));

	}

	@Test
	public void logoutUser_InValidDetails_thenFail(){

		AuthResponseDto authResponseDto=new AuthResponseDto();
		authResponseDto.setStatus("Failed");

		when(tokenValidator.getissuer(Mockito.anyString())).thenReturn("issuer-mock");
		ResponseEntity<String> mockResponse = new ResponseEntity<>("mockResponse", HttpStatus.BAD_REQUEST);
		Mockito.when(authRestTemplate.getForEntity(
						ArgumentMatchers.anyString(),
						ArgumentMatchers.<Class<String>>any()))
				.thenReturn(mockResponse);
		AuthResponseDto authResponseDtoResponse=authService.logoutUser("mock-token");
		assertThat(authResponseDtoResponse.getStatus(),is(authResponseDto.getStatus()));

	}

	@Test
	public void loginRedirect_ValidDetails_thenPass() throws Exception {

		ReflectionTestUtils.setField(authService, "tokenEndpoint", "http://localhost:8080/auth/realms/mosip/protocol/openid-connect/auth");

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");

		ResponseEntity<String> res = new ResponseEntity<>("resEntity", HttpStatus.OK);
		Mockito.when(authRestTemplate.exchange(Mockito.anyString(), Mockito.eq(HttpMethod.POST), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(res);

		Mockito.when(objectMapper.readValue(Mockito.anyString(), Mockito.any(Class.class))).thenReturn(accessTokenResponse);

		authService.loginRedirect("mock-state", "mock-sessionState", "mock-code", "mock-state", "mock-redirectURI");
	}


	@Test
	public void refreshToken_ValidDetails_thenPass() throws Exception {

		ReflectionTestUtils.setField(authService, "tokenEndpoint", "http://localhost:8080/auth/realms/mosip/protocol/openid-connect/auth");

		RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
		refreshTokenRequest.setClientSecret("mock-client");
		refreshTokenRequest.setClientID("mock-client-id");

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(ResponseEntity.ok(accessTokenResponse));

		authService.refreshToken("app-id","refresh-token",refreshTokenRequest);
	}

	@Test
	public void refreshToken_InValidDetails_thenFail() throws Exception {

		ReflectionTestUtils.setField(authService, "tokenEndpoint", "http://localhost:8080/auth/realms/mosip/protocol/openid-connect/auth");

		RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
		refreshTokenRequest.setClientSecret("mock-client");
		refreshTokenRequest.setClientID("mock-client-id");

		AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
		accessTokenResponse.setAccess_token("mock-access-token");
		accessTokenResponse.setExpires_in("111");
		accessTokenResponse.setRefresh_token("mock-ref-token");

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "mosip");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakOpenIdUrl + "/token");
		when(authRestTemplate.postForEntity(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toUriString()),
				Mockito.any(), Mockito.eq(AccessTokenResponse.class))).thenReturn(ResponseEntity.ok(null));
		try{
			authService.refreshToken("app-id","refresh-token",refreshTokenRequest);
		}catch (AuthManagerException e){
			assertThat(e.getErrorCode(),is(AuthErrorCode.CLIENT_ERROR.getErrorCode()));
		}
	}

	@Test
	public void valdiateToken_ValidInDetails_thenPass() throws Exception {
		MosipUserTokenDto mosipUserTokenDto = new MosipUserTokenDto();

		ResponseEntity<String> res = new ResponseEntity<>("resEntity", HttpStatus.UNAUTHORIZED);
		Mockito.when(authRestTemplate.exchange(Mockito.anyString(), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "401", "not auth".getBytes(),
				Charset.defaultCharset()));;

		Mockito.when(objectMapper.readValue(Mockito.anyString(), Mockito.any(Class.class))).thenReturn(new KeycloakErrorResponseDto());
		try{
			authService.valdiateToken("eyJraWQiOiJfRjlScFNybEczWGM4elkxRTFPMFZuZWhxSnlBV2pjdTdpcUlURVRMTFVzIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIxLTMxZjQyMmI5LWUwMjktNDc1OC1hYjQ5LTY2YmNmZDZlZDc5NSIsImF1ZCI6Imh0dHBzOlwvXC9lc2lnbmV0LWluc3VyYW5jZS5xYS1pbmppMS5tb3NpcC5uZXRcL3YxXC9lc2lnbmV0XC92Y2lcL2NyZWRlbnRpYWwiLCJjX25vbmNlX2V4cGlyZXNfaW4iOjQwLCJjX25vbmNlIjoiZk5SdU51VjZ0MWU2UUJXQVZMd0siLCJzY29wZSI6InN1bmJpcmRfcmNfaW5zdXJhbmNlX3ZjX2xkcCIsImlzcyI6Imh0dHBzOlwvXC9lc2lnbmV0LWluc3VyYW5jZS5xYS1pbmppMS5tb3NpcC5uZXRcL3YxXC9lc2lnbmV0IiwiZXhwIjoxNzA4Njk4MjQ1LCJpYXQiOjE3MDg2OTQ2NDUsImNsaWVudF9pZCI6ImthaWYtdGVzdGluZy1wYXJ0bmVyIn0.GOjKKwiLFEkRtLNUvkTI5Tnf9iCC2Uq4PIVfTGsbuyoeJEUgZvl0myn9mIMTs2LvCM_8Ezcbr5wqzbODmLsfcOMhKDLEIvELOo9Px7b1JdESfl9aPLouEFbMzcLXvS91teKRBRTDjOK5ycxn-pGoAocEOR2bZTMKxVDy6jEVH2iCqhGgtECPAfgRufoD6aTVG57W727mgzvI20qvz-PA8nT3jROaQ4CzOyZqxx5Hq1lDr9UI7TVpvmhxFj1fR3epC0YG8Tj1sk1_nTXa9KALaFcY0FOYMB0M672snCRafh3VngY1SWIMkOgXrgpA9W-v6DNcK3OegHAiuXIJEASXog");
		}catch (AuthenticationServiceException e){
			assertThat(e.getMessage(),is(AuthErrorCode.INVALID_TOKEN.getErrorMessage()+"null"));
		}
	}



}
