package io.mosip.kernel.auth.service.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.auth.defaultimpl.dto.AuthToken;
import io.mosip.kernel.auth.defaultimpl.dto.TimeToken;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultimpl.service.TokenService;
import io.mosip.kernel.auth.defaultimpl.service.impl.TokenServicesImpl;
import io.mosip.kernel.auth.test.AuthTestBootApplication;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class TokenServiceImplTest {

	TokenService tokenService = null;

	@Before
	public void init() {
		DataSourceBuilder dataSourceBuilder = DataSourceBuilder.create();
		dataSourceBuilder.driverClassName("org.h2.Driver");
		dataSourceBuilder.url("jdbc:h2:mem:mosip_iam");
		dataSourceBuilder.username("SA");
		dataSourceBuilder.password("");
		tokenService = new TokenServicesImpl(dataSourceBuilder.build());
	}

	@Test
	public void storeTokenTest() throws Exception {
		AuthToken authToken = new AuthToken();
		authToken.setUserId("abc");
		authToken.setAccessToken("mock-access-token");
		authToken.setExpirationTime(2000);
		authToken.setRefreshToken("mock-refresh-token");
		tokenService.StoreToken(authToken);
	}
	
	@Test
	public void storeupdateTokenTest() throws Exception {
		AuthToken authToken = new AuthToken();
		authToken.setUserId("abc6");
		authToken.setAccessToken("mock-access-token9");
		authToken.setExpirationTime(2000);
		authToken.setRefreshToken("mock-refresh-token9");
		tokenService.StoreToken(authToken);
		AuthToken authTokenN = new AuthToken();
		authTokenN.setUserId("abc6");
		authTokenN.setAccessToken("mock-access-token10");
		authTokenN.setExpirationTime(2000);
		authTokenN.setRefreshToken("mock-refresh-token10");
		tokenService.StoreToken(authTokenN);
	}
	
	@Test
	public void updateTokenTest() throws Exception {
		AuthToken authTokenFirst = new AuthToken();
		authTokenFirst.setUserId("abc1");
		authTokenFirst.setAccessToken("mock-access-token1");
		authTokenFirst.setExpirationTime(2000);
		authTokenFirst.setRefreshToken("mock-refresh-token1");
		tokenService.StoreToken(authTokenFirst);
		AuthToken authToken = new AuthToken();
		authToken.setUserId("abc1");
		authToken.setAccessToken("mock-access-token2");
		authToken.setExpirationTime(2000);
		authToken.setRefreshToken("mock-refresh-token2");
		tokenService.UpdateToken(authToken);
	}
	
	
	@Test
	public void getTokenDetailsTest() throws Exception {
		AuthToken authToken=tokenService.getTokenDetails("mock-access-token11");
		assertNull(authToken);
	}
	
	
	@Test
	public void getTokenDetailsNullTest() throws Exception {
		AuthToken authTokenFirst = new AuthToken();
		authTokenFirst.setUserId("abc2");
		authTokenFirst.setAccessToken("mock-access-token3");
		authTokenFirst.setExpirationTime(2000);
		authTokenFirst.setRefreshToken("mock-refresh-token3");
		tokenService.StoreToken(authTokenFirst);
		AuthToken authToken=tokenService.getTokenDetails("mock-access-token3");
		assertThat(authToken.getUserId(),is(authTokenFirst.getUserId()));
	}
	
	
	@Test
	public void getUpdatedAccessTokenTest() throws Exception {
		TimeToken timeToken = new TimeToken();
		timeToken.setToken("new-mock-token5");
		timeToken.setExpTime(3000);
		AuthToken authTokenFirst = new AuthToken();
		authTokenFirst.setUserId("abc3");
		authTokenFirst.setAccessToken("mock-access-token4");
		authTokenFirst.setExpirationTime(2000);
		authTokenFirst.setRefreshToken("mock-refresh-token4");
		tokenService.StoreToken(authTokenFirst);
		AuthToken authToken=tokenService.getUpdatedAccessToken("mock-access-token4",timeToken,"abc3");
		assertThat(authToken.getUserId(),is(authTokenFirst.getUserId()));
	}
	
	
	@Test
	public void getTokenBasedOnNameTest() throws Exception {
		
		AuthToken authTokenFirst = new AuthToken();
		authTokenFirst.setUserId("abc4");
		authTokenFirst.setAccessToken("mock-access-token6");
		authTokenFirst.setExpirationTime(2000);
		authTokenFirst.setRefreshToken("mock-refresh-token6");
		tokenService.StoreToken(authTokenFirst);
		AuthToken authToken=tokenService.getTokenBasedOnName("abc4");
		assertThat(authToken.getAccessToken(),is(authTokenFirst.getAccessToken()));
	}
	
	@Test
	public void getTokenBasedOnNameNullTest() throws Exception {
		AuthToken authToken=tokenService.getTokenBasedOnName("abc7");
		assertNull(authToken);
	}
	
	
	@Test
	public void revokeTokenTest() throws Exception {
		
		AuthToken authTokenFirst = new AuthToken();
		authTokenFirst.setUserId("abc5");
		authTokenFirst.setAccessToken("mock-access-token7");
		authTokenFirst.setExpirationTime(2000);
		authTokenFirst.setRefreshToken("mock-refresh-token7");
		tokenService.StoreToken(authTokenFirst);
		tokenService.revokeToken("mock-access-token7");
	}
	
	@Test(expected = AuthManagerException.class)
	public void revokeTokenAuthManagerExceptionTest() throws Exception {
		tokenService.revokeToken("mock-access-token8");
	}
}
