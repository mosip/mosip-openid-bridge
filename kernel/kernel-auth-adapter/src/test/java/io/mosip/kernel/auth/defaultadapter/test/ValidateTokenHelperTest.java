package io.mosip.kernel.auth.defaultadapter.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestBodyUriSpec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.helper.ValidateTokenHelper;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;
import reactor.core.publisher.Mono;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
public class ValidateTokenHelperTest {

	@Autowired
	private ObjectMapper mapper;

	@Value("${auth.server.admin.oidc.certs.path:/protocol/openid-connect/certs}")
	private String certsPath;

	@Value("${auth.server.admin.oidc.userinfo.path:/protocol/openid-connect/userinfo}")
	private String userInfo;

	@Value("${auth.server.admin.issuer.domain.validate:true}")
	private boolean validateIssuerDomain;

	@Value("${auth.server.admin.issuer.uri:}")
	private String issuerURI;

	@Value("${auth.server.admin.issuer.internal.uri:}")
	private String issuerInternalURI;

	@Value("${auth.server.admin.audience.claim.validate:true}")
	private boolean validateAudClaim;

	@Autowired
	private ValidateTokenHelper validateTokenHelper;

	private RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
	private WebClient webClient = Mockito.mock(WebClient.class);

	@Test
	public void doOnlineTokenValidationTest() throws Exception {
		String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		String userInfoPath = issuerInternalURI + "mosip" + userInfo;
		String resp = "{\r\n" + "  \"error\": \"Forbidden\",\r\n" + "  \"error_description\": \"forbidden\" }";
		when(restTemplate.exchange(Mockito.eq(userInfoPath), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class)))
						.thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", resp.getBytes(),
								Charset.defaultCharset()));
		ImmutablePair<HttpStatus, MosipUserDto> res = validateTokenHelper.doOnlineTokenValidation(token, restTemplate);
		assertNull(res.getValue());
	}

	@Test
	public void doOnlineTokenValidationWebClientTest() throws Exception {
		String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		String userInfoPath = issuerInternalURI + "mosip" + userInfo;
		RequestBodyUriSpec requestBodyUriSpec = Mockito.mock(RequestBodyUriSpec.class);
		String resp = "{\"access_token\":\"mock-token\"}";
		when(webClient.method(HttpMethod.GET)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.uri(userInfoPath)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.headers(Mockito.any())).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.exchange()).thenReturn(Mono.just(
				ClientResponse.create(HttpStatus.OK).header("Content-type", "application/json").body(resp).build()));
		ImmutablePair<HttpStatus, MosipUserDto> res = validateTokenHelper.doOnlineTokenValidation(token, webClient);
		assertThat(res.getRight().getUserId(), is("service-account-mosip-resident-client"));
	}

	// bug as response is as text not to string
	/*
	 * @Test public void doOnlineTokenValidationWebClientUnAuthTest() throws
	 * Exception { String token=
	 * "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
	 * String userInfoPath = issuerURI + "mosip" + userInfo; RequestBodyUriSpec
	 * requestBodyUriSpec = Mockito.mock(RequestBodyUriSpec.class); String resp =
	 * "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n" +
	 * "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" +
	 * "  \"metadata\": {},\r\n" + "  \"response\": { },\r\n" +
	 * "  \"errors\": [{ \"errorCode\": \"KER-ATH-401\", \"message\": \"unauth\" } ]\r\n"
	 * + "}"; when(webClient.method(HttpMethod.GET)).thenReturn(requestBodyUriSpec);
	 * when(requestBodyUriSpec.uri(userInfoPath)).thenReturn(requestBodyUriSpec);
	 * when(requestBodyUriSpec.headers(Mockito.any())).thenReturn(requestBodyUriSpec
	 * ); when(requestBodyUriSpec.exchange()).thenReturn(Mono.just(ClientResponse.
	 * create(HttpStatus.OK).header("Content-type",
	 * "application/json").body(resp).build())); ImmutablePair<HttpStatus,
	 * MosipUserDto> res
	 * =validateTokenHelper.doOnlineTokenValidation(token,webClient);
	 * assertThat(res.getKey(),is(HttpStatus.UNAUTHORIZED)); }
	 */

	@Test
	public void doOnlineTokenValidationWebClientErrorTest() throws Exception {
		String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		String userInfoPath = issuerInternalURI + "mosip" + userInfo;
		RequestBodyUriSpec requestBodyUriSpec = Mockito.mock(RequestBodyUriSpec.class);
		String resp = "{\"access_token\":\"mock-token\"}";
		when(webClient.method(HttpMethod.GET)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.uri(userInfoPath)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.headers(Mockito.any())).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.exchange()).thenReturn(Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED)
				.header("Content-type", "application/json").body(resp).build()));
		ImmutablePair<HttpStatus, MosipUserDto> res = validateTokenHelper.doOnlineTokenValidation(token, webClient);
		assertThat(res.getKey(), is(HttpStatus.UNAUTHORIZED));
	}

	@Test
	public void doOfflineTokenValidationTest() throws Exception {
		String token = JWT.create().withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.sign(Algorithm.none());

		MosipUserDto res = validateTokenHelper.doOfflineLocalTokenValidation(token);
		assertThat(res.getName(), is("mock-user"));

	}

	@Test
	public void isTokenValidTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(
				JWT.require(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate())).build()
						.verify(token),
				kp.getPublic());
		assertThat(res.left, is(true));
	}

	@Test
	public void isTokenInvalidExpiryTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now().minusSeconds(345600)))
				.withExpiresAt(Date.from(Instant.now().minusSeconds(100000))).withAudience(new String[] { "account" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenInvalidIssuerTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://dev.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenInvalidSignatureTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));
		kp = kpg.generateKeyPair();
		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}
	
	@Test
	public void isTokenInvalidAUDTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "abc")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "abc" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(
				JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.FORBIDDEN));
	}
}
