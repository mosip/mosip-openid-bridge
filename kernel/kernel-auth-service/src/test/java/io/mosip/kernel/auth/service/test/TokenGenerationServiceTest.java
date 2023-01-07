package io.mosip.kernel.auth.service.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.auth.defaultimpl.service.TokenGenerationService;
import io.mosip.kernel.auth.test.AuthTestBootApplication;
import io.mosip.kernel.core.authmanager.model.AuthNResponseDto;
import io.mosip.kernel.core.authmanager.spi.AuthService;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class TokenGenerationServiceTest {


	@Autowired
	private TokenGenerationService tokenGenerationService;
	
	@MockBean
	AuthService authService;

	@Value("${mosip.kernel.auth.app.id}")
	private String authAppId;

	@Value("${mosip.kernel.auth.client.id}")
	private String clientId;

	@Value("${mosip.kernel.auth.secret.key}")
	private String secretKey;

	@Value("${mosip.kernel.ida.app.id}")
	private String idaAppId;

	@Value("${mosip.kernel.ida.client.id}")
	private String idaClientId;

	@Value("${mosip.kernel.ida.secret.key}")
	private String idaSecretKey;
	
	
	@Test
	public void getInternalTokenGenerationServiceTest() throws Exception  {
		AuthNResponseDto authNResponseDto = new AuthNResponseDto();
		authNResponseDto.setToken("Mock-token");
		when(authService.authenticateWithSecretKey(Mockito.any())).thenReturn(authNResponseDto);
		assertThat(tokenGenerationService.getInternalTokenGenerationService(),is("Mock-token"));
	}
}
