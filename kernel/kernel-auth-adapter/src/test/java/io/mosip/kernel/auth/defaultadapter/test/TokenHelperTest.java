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
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.auth.defaultadapter.config.RestTemplateInterceptor;
import io.mosip.kernel.auth.defaultadapter.exception.AuthRestException;
import io.mosip.kernel.auth.defaultadapter.handler.AuthHandler;
import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.AuthToken;
import io.mosip.kernel.core.authmanager.authadapter.model.MosipUserDto;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
public class TokenHelperTest {

	@Value("${auth.server.admin.issuer.uri:}")
    private String issuerURI;
	
	@Autowired
	private ObjectMapper mapper;

	@Value("#{${mosip.kernel.auth.appids.realm.map}}")
	private Map<String, String> realmMap;

	@Value("${auth.server.admin.oidc.token.path:/protocol/openid-connect/token}")
    private String tokenPath;
	
	@Autowired
	private TokenHelper tokenHelper;
	
	
	private RestTemplate restTemplate = Mockito.mock(RestTemplate.class);

	public void init() {
		
	}
	
	
	@Test
	public void getClientTokenTest() throws Exception {
		String tokenUrl = new StringBuilder(issuerURI).append("mosip").append(tokenPath).toString();
		String resp= "{\"access_token\":\"mock-token\"}";
		when(restTemplate.postForEntity(Mockito.eq(tokenUrl),Mockito.any(),Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", restTemplate);
	    assertTrue(token.equals("mock-token"));
	}
	
	@Test
	public void getClientTokenHttpExceptionTest() throws Exception {
		String tokenUrl = new StringBuilder(issuerURI).append("mosip").append(tokenPath).toString();
		String resp= "{\"error\":\"not found\"}";
		when(restTemplate.postForEntity(Mockito.eq(tokenUrl),Mockito.any(),Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "404", resp.getBytes(),
				Charset.defaultCharset()));;
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", restTemplate);
	    assertNull(token);
	}
	
	@Test(expected = AuthRestException.class)
	public void getClientTokenAuthRestExceptionTest() throws Exception {
		String tokenUrl = new StringBuilder(issuerURI).append("mosip").append(tokenPath).toString();
		String resp="{ \"errors\": [{\"errorCode\":\"KER-ATH-001\",\"message\":\"no token\"}]}";
		when(restTemplate.postForEntity(Mockito.eq(tokenUrl),Mockito.any(),Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", restTemplate);
	    assertNull(token);
	}
	
	@Test
	public void getTokenValidatedVertxUserResponse() throws Exception {
		String tokenUrl = new StringBuilder(issuerURI).append("mosip").append(tokenPath).toString();
		String resp= "{error\":\"not found\"}";
		when(restTemplate.postForEntity(Mockito.eq(tokenUrl),Mockito.any(),Mockito.eq(String.class))).thenReturn(ResponseEntity.ok(resp));
		String token=tokenHelper.getClientToken("mock-clientID", "mock-clientSecret", "ida", restTemplate);
	    assertNull(token);
	}
	
	
	
	
}
