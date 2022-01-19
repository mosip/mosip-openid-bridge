package io.mosip.kernel.auth.keycloak.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultimpl.config.MosipEnvironment;
import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.dto.AccessTokenResponse;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultimpl.exception.LoginException;
import io.mosip.kernel.auth.defaultimpl.repository.UserStoreFactory;
import io.mosip.kernel.auth.defaultimpl.repository.impl.KeycloakImpl;
import io.mosip.kernel.auth.defaultimpl.service.OTPService;
import io.mosip.kernel.auth.defaultimpl.service.TokenService;
import io.mosip.kernel.auth.defaultimpl.service.UinService;
import io.mosip.kernel.auth.defaultimpl.util.AuthUtil;
import io.mosip.kernel.auth.defaultimpl.util.TemplateUtil;
import io.mosip.kernel.auth.defaultimpl.util.TokenGenerator;
import io.mosip.kernel.auth.defaultimpl.util.TokenValidator;
import io.mosip.kernel.auth.test.AuthTestBootApplication;
import io.mosip.kernel.core.authmanager.model.AccessTokenResponseDTO;
import io.mosip.kernel.core.authmanager.model.AuthNResponse;
import io.mosip.kernel.core.authmanager.model.AuthNResponseDto;
import io.mosip.kernel.core.authmanager.model.AuthZResponseDto;
import io.mosip.kernel.core.authmanager.model.IndividualIdDto;
import io.mosip.kernel.core.authmanager.model.MosipUserDto;
import io.mosip.kernel.core.authmanager.model.MosipUserListDto;
import io.mosip.kernel.core.authmanager.model.MosipUserSalt;
import io.mosip.kernel.core.authmanager.model.MosipUserSaltListDto;
import io.mosip.kernel.core.authmanager.model.MosipUserTokenDto;
import io.mosip.kernel.core.authmanager.model.PasswordDto;
import io.mosip.kernel.core.authmanager.model.RIdDto;
import io.mosip.kernel.core.authmanager.model.Role;
import io.mosip.kernel.core.authmanager.model.RolesListDto;
import io.mosip.kernel.core.authmanager.model.UserDetailsDto;
import io.mosip.kernel.core.authmanager.model.UserDetailsResponseDto;
import io.mosip.kernel.core.authmanager.model.UserNameDto;
import io.mosip.kernel.core.authmanager.model.UserOtp;
import io.mosip.kernel.core.authmanager.model.UserPasswordRequestDto;
import io.mosip.kernel.core.authmanager.model.UserPasswordResponseDto;
import io.mosip.kernel.core.authmanager.model.UserRegistrationRequestDto;
import io.mosip.kernel.core.authmanager.model.UserRoleDto;
import io.mosip.kernel.core.authmanager.model.ValidationResponseDto;
import io.mosip.kernel.core.authmanager.spi.AuthService;
import io.mosip.kernel.core.util.StringUtils;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class KeycloakImplTest {

	@Qualifier(value = "keycloakRestTemplate")
	@MockBean
	private RestTemplate restTemplate;

	@Autowired
	private AuthUtil authUtil;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private KeycloakImpl keycloakImpl;

	@Value("${mosip.iam.roles-extn-url}")
	private String roles;

	@Value("${mosip.iam.users-extn-url}")
	private String users;

	@Value("${mosip.iam.role-user-mapping-url}")
	private String roleUserMappingurl;

	@Value("${mosip.iam.realm.operations.base-url}")
	private String keycloakBaseUrl;

	@Value("${mosip.iam.admin-url}")
	private String keycloakAdminUrl;

	@Value("${mosip.iam.admin-realm-id}")
	private String adminRealmId;

	@Value("${mosip.keycloak.max-no-of-users:100}")
	private String maxUsers;
	
	@Value("${mosip.iam.role-based-user-url}")
	private String roleBasedUsersurl;

//	restTemplate.exchange(url, httpMethod, requestEntity, String.class);

	@Before
	public void init() {
		NamedParameterJdbcTemplate jdbcTemplate = Mockito.mock(NamedParameterJdbcTemplate.class);
		ReflectionTestUtils.setField(keycloakImpl, "jdbcTemplate", jdbcTemplate);
	}

	@Test
	public void getAllRolesTest() throws Exception {

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakAdminUrl + roles);
		String userIDResp = "[\r\n" + "  {\r\n" + "    \"name\": \"PROCESSOR\"  }\r\n" + "]";
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		RolesListDto rolesListDto = keycloakImpl.getAllRoles("ida");
		assertThat(rolesListDto.getRoles().get(0).getRoleName(), is("PROCESSOR"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getAllRolesIOExceptionTest() throws Exception {

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakAdminUrl + roles);
		String userIDResp = "[\r\n" + "  \r\n" + "    \"name\": \"PROCESSOR\"  }\r\n" + "]";
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		RolesListDto rolesListDto = keycloakImpl.getAllRoles("ida");
		assertThat(rolesListDto.getRoles().get(0).getRoleName(), is("PROCESSOR"));
	}

	@Test
	public void getListOfUsersDetailsTest() throws Exception {

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakAdminUrl + users);
		uriComponentsBuilder.queryParam("max", maxUsers);
		String userIDResp = "[{\"username\": \"mock-user\",\"email\": \"mock@mosip.io\",\"firstName\": \"fname\",\"lastName\": \"lname\",\"id\": \"829329\",\"attributes\":{\"mobile\":[\"8291930201\"],\"rid\":[\"728391\"],\"name\":[\"mock-name\"]} }]";
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		// role
		Map<String, String> rolePathParams = new HashMap<>();
		rolePathParams.put(AuthConstant.REALM_ID, "ida");
		rolePathParams.put("userId", "829329");

		UriComponentsBuilder rolePathParamsUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + roleUserMappingurl);
		String roleResp = "[\r\n" + "  {\r\n" + "    \"name\": \"PROCESSOR\"  }\r\n" + "]";
		String roleUrl = rolePathParamsUriComponentsBuilder.buildAndExpand(rolePathParams).toString();
		when(restTemplate.exchange(Mockito.eq(roleUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(roleResp));
		List<String> userd = new ArrayList<>();
		userd.add("mock-user");
		MosipUserListDto rolesListDto = keycloakImpl.getListOfUsersDetails(userd, "ida");
		assertThat(rolesListDto.getMosipUserDtoList().get(0).getName(), is("mock-name"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getListOfUsersDetailsIOExceptionTest() throws Exception {

		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakAdminUrl + users);
		uriComponentsBuilder.queryParam("max", maxUsers);
		String userIDResp = "[\"username\": \"mock-user\",\"email\": \"mock@mosip.io\",\"firstName\": \"fname\",\"lastName\": \"lname\",\"id\": \"829329\",\"attributes\":{\"mobile\":[\"8291930201\"],\"rid\":[\"728391\"],\"name\":[\"mock-name\"]} }]";
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		// role
		Map<String, String> rolePathParams = new HashMap<>();
		rolePathParams.put(AuthConstant.REALM_ID, "ida");
		rolePathParams.put("userId", "829329");

		UriComponentsBuilder rolePathParamsUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + roleUserMappingurl);
		String roleResp = "[\r\n" + "  {\r\n" + "    \"name\": \"PROCESSOR\"  }\r\n" + "]";
		String roleUrl = rolePathParamsUriComponentsBuilder.buildAndExpand(rolePathParams).toString();
		when(restTemplate.exchange(Mockito.eq(roleUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(roleResp));
		List<String> userd = new ArrayList<>();
		userd.add("mock-user");
		MosipUserListDto rolesListDto = keycloakImpl.getListOfUsersDetails(userd, "ida");
		assertThat(rolesListDto.getMosipUserDtoList().get(0).getName(), is("mock-name"));
	}

	@Test
	public void getRidFromUserIdTest() throws Exception {
		String userIDResp = "[{\"username\": \"mock-user\",\"attributes\":{\"rid\":[\"8291930201\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + "?username=" + "mock-user");
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		RIdDto rolesListDto = keycloakImpl.getRidFromUserId("mock-user", "ida");
		assertThat(rolesListDto.getRId(), is("8291930201"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getRidFromUserIdNullRespTest() throws Exception {
		String userIDResp = "[{\"username\": \"mock-user\",\"attributes\":{\"rid\":[\"8291930201\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + "?username=" + "mock-user");
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(null));
		RIdDto rolesListDto = keycloakImpl.getRidFromUserId("mock-user", "ida");
		assertThat(rolesListDto.getRId(), is("8291930201"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getRidFromUserIdUserNotFoundTest() throws Exception {
		String userIDResp = "[{\"username\": \"mock-user1\",\"attributes\":{\"rid\":[\"8291930201\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + "?username=" + "mock-user");
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		RIdDto rolesListDto = keycloakImpl.getRidFromUserId("mock-user", "ida");
		assertThat(rolesListDto.getRId(), is("8291930201"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getRidFromUserIdIOExpTest() throws Exception {
		String userIDResp = "[\"username\": \"mock-user\",\"attributes\":{\"rid\":[\"8291930201\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + "?username=" + "mock-user");
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		RIdDto rolesListDto = keycloakImpl.getRidFromUserId("mock-user", "ida");
		assertThat(rolesListDto.getRId(), is("8291930201"));
	}

	/*
	 * @Test public void registerUserUserNotPresentTest() throws Exception { //is
	 * user already present Map<String, String> registerPathParams = new
	 * HashMap<>(); registerPathParams.put(AuthConstant.REALM_ID,
	 * "preregistration"); UriComponentsBuilder uriComponentsBuilder =
	 * UriComponentsBuilder
	 * .fromUriString(keycloakBaseUrl.concat("/users?username=").concat("112211"));
	 * when(restTemplate.exchange(
	 * Mockito.eq(uriComponentsBuilder.buildAndExpand(registerPathParams).toString()
	 * ), Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
	 * .thenReturn(null);
	 * 
	 * // get useridfrom id String userIDResp = "[\r\n" + "  {\r\n" +
	 * "    \"username\": \"112211\",\r\n" + "    \"id\": \"8282828282\"\r\n" +
	 * "  }\r\n" + "]"; UriComponentsBuilder getUserIDUriComponentsBuilder =
	 * UriComponentsBuilder
	 * .fromUriString(keycloakBaseUrl.concat("/users?username=").concat("112211"));
	 * when(restTemplate.exchange(
	 * Mockito.eq(getUserIDUriComponentsBuilder.buildAndExpand(registerPathParams).
	 * toString()), Mockito.eq(HttpMethod.GET), Mockito.any(),
	 * Mockito.eq(String.class))) .thenReturn(ResponseEntity.ok(userIDResp));
	 * 
	 * // get role ID
	 * 
	 * Map<String, String> roleIDPathParams = new HashMap<>();
	 * roleIDPathParams.put(AuthConstant.REALM_ID, "preregistration");
	 * roleIDPathParams.put("roleName", "INDIVIDUAL"); UriComponentsBuilder
	 * rolIDUriComponentsBuilder =
	 * UriComponentsBuilder.fromUriString(keycloakBaseUrl + "/roles/" +
	 * "INDIVIDUAL"); // get useridfromid String roleIDResp = "  {\r\n" +
	 * "    \"id\": \"8282828282\"\r\n" + "  }"; when(restTemplate.exchange(
	 * Mockito.eq(rolIDUriComponentsBuilder.buildAndExpand(roleIDPathParams).
	 * toString()), Mockito.eq(HttpMethod.GET), Mockito.any(),
	 * Mockito.eq(String.class))) .thenReturn(ResponseEntity.ok(roleIDResp));
	 * 
	 * // map roles UriComponentsBuilder roleMapperUriComponentsBuilder
	 * =UriComponentsBuilder.fromUriString(keycloakBaseUrl.concat(
	 * "/users/{userID}/role-mappings/realm")); registerPathParams.put("userID",
	 * "112211");
	 * when(restTemplate.exchange(Mockito.eq(roleMapperUriComponentsBuilder.
	 * buildAndExpand(registerPathParams).toString()), Mockito.eq(HttpMethod.POST),
	 * Mockito.any(), Mockito.eq(String.class)))
	 * .thenReturn(ResponseEntity.ok("{}"));
	 * 
	 * UserRegistrationRequestDto userRegistrationRequestDto = new
	 * UserRegistrationRequestDto(); userRegistrationRequestDto.setAppId("prereg");
	 * userRegistrationRequestDto.setUserName("112211");
	 * 
	 * MosipUserDto rolesListDto =
	 * keycloakImpl.registerUser(userRegistrationRequestDto);
	 * assertThat(rolesListDto.getUserId(), is("112211"));
	 * 
	 * }
	 */

	@Test
	public void getIndividualIdFromUserIdTest() throws Exception {
		String userIDResp = "[{\"username\": \"mock-user\",\"attributes\":{\"individualId\":[\"8291930201\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + "?username=" + "mock-user");
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		IndividualIdDto rolesListDto = keycloakImpl.getIndividualIdFromUserId("mock-user", "ida");
		assertThat(rolesListDto.getIndividualId(), is("8291930201"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getIndividualIdFromUserIdAuthManagerExceptionTest() throws Exception {
		String userIDResp = "[{\"username\": \"mock-user1\",\"attributes\":{\"individualId\":[\"8291930201\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + "?username=" + "mock-user");
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		IndividualIdDto rolesListDto = keycloakImpl.getIndividualIdFromUserId("mock-user", "ida");
		rolesListDto.getIndividualId();
	}
	
	@Test(expected = AuthManagerException.class)
	public void getIndividualIdFromUserIdIOTest() throws Exception {
		String userIDResp = "[\"username\": \"mock-user\",\"attributes\":{\"individualId\":[\"8291930201\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + "?username=" + "mock-user");
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));
		IndividualIdDto rolesListDto = keycloakImpl.getIndividualIdFromUserId("mock-user", "ida");
		rolesListDto.getIndividualId();
	}
	
	@Test(expected = AuthManagerException.class)
	public void getIndividualIdFromUserIdNullRespTest() throws Exception {
		String userIDResp = "[{\"username\": \"mock-user1\",\"attributes\":{\"individualId\":[\"8291930201\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + "?username=" + "mock-user");
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(null));
		IndividualIdDto rolesListDto = keycloakImpl.getIndividualIdFromUserId("mock-user", "ida");
		rolesListDto.getIndividualId();
	}

	@Test
	public void getListOfUsersDetailsSearchTest() throws Exception {
		String userIDResp = "[{\"username\": \"mock-user\",\"email\": \"mock@mosip.io\",\"firstName\": \"fname\",\"lastName\": \"lname\",\"id\": \"829329\",\"attributes\":{\"mobile\":[\"8291930201\"],\"rid\":[\"728391\"],\"name\":[\"mock-name\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.REALM_ID, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(keycloakAdminUrl + users);
		uriComponentsBuilder.queryParam("email", "mock@mosip.io");
		uriComponentsBuilder.queryParam("firstName", "fname");
		uriComponentsBuilder.queryParam("lastName", "lname");
		uriComponentsBuilder.queryParam("username", "username");
		uriComponentsBuilder.queryParam("search", "search");
		uriComponentsBuilder.queryParam("first", 0);
		uriComponentsBuilder.queryParam("max", 10);
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));

		// role
		Map<String, String> rolePathParams = new HashMap<>();
		rolePathParams.put(AuthConstant.REALM_ID, "ida");
		rolePathParams.put("userId", "829329");

		UriComponentsBuilder rolePathParamsUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + roleUserMappingurl);
		String roleResp = "[\r\n" + "  {\r\n" + "    \"name\": \"PROCESSOR\"  }\r\n" + "]";
		String roleUrl = rolePathParamsUriComponentsBuilder.buildAndExpand(rolePathParams).toString();
		when(restTemplate.exchange(Mockito.eq(roleUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(roleResp));
		MosipUserListDto rolesListDto = keycloakImpl.getListOfUsersDetails("ida", null, 0, 10, "mock@mosip.io", "fname",
				"lname", "username", "search");
		assertThat(rolesListDto.getMosipUserDtoList().get(0).getName(), is("mock-name"));
	}

	@Test
	public void getListOfUsersDetailsRoleSearchTest() throws Exception {
		String userIDResp = "[{\"username\": \"mock-user\",\"email\": \"mock@mosip.io\",\"firstName\": \"fname\",\"lastName\": \"lname\",\"id\": \"829329\",\"attributes\":{\"mobile\":[\"8291930201\"],\"rid\":[\"728391\"],\"name\":[\"mock-name\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.ROLE_NAME, "PROCESSOR");
		pathParams.put(AuthConstant.REALM, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + roleBasedUsersurl);
		uriComponentsBuilder.queryParam("first", 0);
		uriComponentsBuilder.queryParam("max", 10);
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));

		// role
		Map<String, String> rolePathParams = new HashMap<>();
		rolePathParams.put(AuthConstant.REALM_ID, "ida");
		rolePathParams.put("userId", "829329");

		UriComponentsBuilder rolePathParamsUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + roleUserMappingurl);
		String roleResp = "[\r\n" + "  {\r\n" + "    \"name\": \"PROCESSOR\"  }\r\n" + "]";
		String roleUrl = rolePathParamsUriComponentsBuilder.buildAndExpand(rolePathParams).toString();
		when(restTemplate.exchange(Mockito.eq(roleUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(roleResp));
		MosipUserListDto rolesListDto = keycloakImpl.getListOfUsersDetails("ida", "PROCESSOR", 0, 10, "mock@mosip.io", "fname",
				"lname", "username", "search");
		assertThat(rolesListDto.getMosipUserDtoList().get(0).getName(), is("mock-name"));
	}
	
	@Test(expected = AuthManagerException.class)
	public void getListOfUsersDetailsRoleSearchIoExceptionTest() throws Exception {
		String userIDResp = "[\"username\": \"mock-user\",\"email\": \"mock@mosip.io\",\"firstName\": \"fname\",\"lastName\": \"lname\",\"id\": \"829329\",\"attributes\":{\"mobile\":[\"8291930201\"],\"rid\":[\"728391\"],\"name\":[\"mock-name\"]} }]";
		Map<String, String> pathParams = new HashMap<>();
		pathParams.put(AuthConstant.ROLE_NAME, "PROCESSOR");
		pathParams.put(AuthConstant.REALM, "ida");
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + roleBasedUsersurl);
		uriComponentsBuilder.queryParam("first", 0);
		uriComponentsBuilder.queryParam("max", 10);
		when(restTemplate.exchange(Mockito.eq(uriComponentsBuilder.buildAndExpand(pathParams).toString()),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
						.thenReturn(ResponseEntity.ok(userIDResp));

		// role
		Map<String, String> rolePathParams = new HashMap<>();
		rolePathParams.put(AuthConstant.REALM_ID, "ida");
		rolePathParams.put("userId", "829329");

		UriComponentsBuilder rolePathParamsUriComponentsBuilder = UriComponentsBuilder
				.fromUriString(keycloakAdminUrl + users + roleUserMappingurl);
		String roleResp = "[\r\n" + "  {\r\n" + "    \"name\": \"PROCESSOR\"  }\r\n" + "]";
		String roleUrl = rolePathParamsUriComponentsBuilder.buildAndExpand(rolePathParams).toString();
		when(restTemplate.exchange(Mockito.eq(roleUrl), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(roleResp));
		MosipUserListDto rolesListDto = keycloakImpl.getListOfUsersDetails("ida", "PROCESSOR", 0, 10, "mock@mosip.io", "fname",
				"lname", "username", "search");
		assertThat(rolesListDto.getMosipUserDtoList().get(0).getName(), is("mock-name"));
	}

}
