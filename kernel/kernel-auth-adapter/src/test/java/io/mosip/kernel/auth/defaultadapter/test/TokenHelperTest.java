package io.mosip.kernel.auth.defaultadapter.test;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestBodyUriSpec;
import org.springframework.web.reactive.function.client.WebClient.RequestHeadersSpec;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultadapter.exception.AuthRestException;
import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import reactor.core.publisher.Mono;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
public class TokenHelperTest {

	@Value("${auth.server.admin.issuer.uri:}")
    private String issuerURI;
	
	@Value("${auth.server.admin.issuer.internal.uri:}")
    private String issuerInternalURI;

	@Autowired
	private ObjectMapper mapper;

	@Value("#{${mosip.kernel.auth.appids.realm.map}}")
	private Map<String, String> realmMap;

	@Value("${auth.server.admin.oidc.token.path:/protocol/openid-connect/token}")
    private String tokenPath;
	
	@Autowired
	private TokenHelper tokenHelper;
	
	
	private RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
	private WebClient webClient = Mockito.mock(WebClient.class);

	public void init() {
		
	}
	
	
	@Test
	public void getClientTokenTest() throws Exception {
		String tokenUrl = new StringBuilder(issuerInternalURI).append("mosip").append(tokenPath).toString();
		String resp= "{\"access_token\":\"mock-token\"}";
		when(restTemplate.postForEntity(Mockito.eq(tokenUrl),Mockito.any(),Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", restTemplate);
	    assertTrue(token.equals("mock-token"));
	}
	
	@Test
	public void getClientTokenHttpExceptionTest() throws Exception {
		String tokenUrl = new StringBuilder(issuerInternalURI).append("mosip").append(tokenPath).toString();
		String resp= "{\"error\":\"not found\"}";
		when(restTemplate.postForEntity(Mockito.eq(tokenUrl),Mockito.any(),Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "404", resp.getBytes(),
				Charset.defaultCharset()));;
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", restTemplate);
	    assertNull(token);
	}
	
	@Test(expected = AuthRestException.class)
	public void getClientTokenAuthRestExceptionTest() throws Exception {
		String tokenUrl = new StringBuilder(issuerInternalURI).append("mosip").append(tokenPath).toString();
		String resp="{ \"errors\": [{\"errorCode\":\"KER-ATH-001\",\"message\":\"no token\"}]}";
		when(restTemplate.postForEntity(Mockito.eq(tokenUrl),Mockito.any(),Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", restTemplate);
	    assertNull(token);
	}
	
	@Test
	public void getTokenValidatedVertxUserResponse() throws Exception {
		String tokenUrl = new StringBuilder(issuerInternalURI).append("mosip").append(tokenPath).toString();
		String resp= "{error\":\"not found\"}";
		when(restTemplate.postForEntity(Mockito.eq(tokenUrl),Mockito.any(),Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", restTemplate);
	    assertNull(token);
	}
	
	
	@Test
	public void getClientTokenWebClientTest() throws Exception {
		String tokenUrl = new StringBuilder(issuerInternalURI).append("mosip").append(tokenPath).toString();
		String resp= "{\"access_token\":\"mock-token\"}";
		RequestBodyUriSpec requestBodyUriSpec = Mockito.mock(RequestBodyUriSpec.class); 
		RequestHeadersSpec  requestHeadersSpec = Mockito.mock(RequestHeadersSpec.class); 
		when(webClient.method(HttpMethod.POST)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.uri(UriComponentsBuilder.fromUriString(tokenUrl).toUriString())).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.contentType(MediaType.APPLICATION_FORM_URLENCODED)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.body(Mockito.any())).thenReturn(requestHeadersSpec);
		when(requestHeadersSpec.exchange()).thenReturn(Mono.just(ClientResponse.create(HttpStatus.OK).header("Content-type", "application/json").body(resp).build()));
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", webClient);
	    assertTrue(token.equals("mock-token"));
	}
	
	@Test
	public void getClientTokenWebClientErrorTest() throws Exception {
		String tokenUrl = new StringBuilder(issuerInternalURI).append("mosip").append(tokenPath).toString();
		String resp= "{\"access_token\":\"mock-token\"}";
		RequestBodyUriSpec requestBodyUriSpec = Mockito.mock(RequestBodyUriSpec.class); 
		RequestHeadersSpec  requestHeadersSpec = Mockito.mock(RequestHeadersSpec.class); 
		when(webClient.method(HttpMethod.POST)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.uri(UriComponentsBuilder.fromUriString(tokenUrl).toUriString())).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.contentType(MediaType.APPLICATION_FORM_URLENCODED)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.body(Mockito.any())).thenReturn(requestHeadersSpec);
		when(requestHeadersSpec.exchange()).thenReturn(Mono.just(ClientResponse.create(HttpStatus.INTERNAL_SERVER_ERROR).header("Content-type", "application/json").body(resp).build()));
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", webClient);
	    assertNull(token);
	}
	
	
}
