package io.mosip.kernel.auth.defaultadapter.test;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.auth.defaultadapter.config.RestTemplateInterceptor;
import io.mosip.kernel.auth.defaultadapter.handler.AuthHandler;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.AuthToken;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
public class AuthHandlerTest extends AuthHandler {

	
	
	@Autowired
	private RestTemplateInterceptor restInterceptor;
	
	@MockBean
	private TokenValidationHelper validationHelper;
	
	@Value("${mosip.kernel.auth.adapter.ssl-bypass:true}")
	private boolean sslBypass;
	
	@Test
	public void retrieveUserTest() throws Exception {

		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setRole("PROCESSOR");
		mosipUserDto.setUserId("110005");
		AuthToken authToken = new AuthToken("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOdjdibklPVmJrakpTNjBSUzF4MW80dlk1SVBweU9LTVpzQWVheWd5TnVJIn0.eyJqdGkiOiI1ZDdmMzQyNy00NzQ0LTQ4YzYtOGFhOC0wNDI5MGFmMzI2MjciLCJleHAiOjE2NTU5NzcxNzksIm5iZiI6MCwiaWF0IjoxNjU1ODkwODU3LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiY2I1YmRiZDItNjdhMy00ZTAzLWEwMDktYjRlNDIxMDc3NmZkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50Iiwibm9uY2UiOiI3ZjlzNjQ4dWhlaCIsImF1dGhfdGltZSI6MTY1NTg5MDc3OSwic2Vzc2lvbl9zdGF0ZSI6IjY0ZDY2MWYxLTRkY2YtNDcxMi05NTNiLWE3NTZlY2QzMGMwZSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly9kZXYubW9zaXAubmV0Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJaT05BTF9BRE1JTiIsIm9mZmxpbmVfYWNjZXNzIiwiUkVHSVNURVJFRF9JTkRJVklEVUFMIiwidW1hX2F1dGhvcml6YXRpb24iLCJHTE9CQUxfQURNSU4iLCJJTkRJVklEVUFMIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSBpZGFfdG9rZW4gaW5kaXZpZHVhbF9pZCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IlVJTiAxMjM0NSIsInByZWZlcnJlZF91c2VybmFtZSI6IjEyMzQ1IiwiZ2l2ZW5fbmFtZSI6IlVJTiIsImZhbWlseV9uYW1lIjoiMTIzNDUiLCJlbWFpbCI6ImxvZ2FuYXRoYW4uc2VrYXJAbWluZHRyZWUuY29tIn0.HnuAzPn72-NFYguNM6XH81Q3yhCJi63ojCgtqNevmXf8WgjusR5cDK1gSx6v9N1_StaXfFKJWNnnxt_Urp5rLlrqMlFIJebqqOPSX2rHFTIKH8TqIntjluzxnp2SU_ccPaMBryZ3H_Qm4GkYYPNnlHC2tltwkUfinRcf_sDa_E5dFDu2ZnCHtrVgsRVeRVJ_LpC9Q6Ea-gp1pSovnVP50HlygzHFCIW8Sj5FmXUBcTud2cloMxRReHtDn3V0RpDrXpjvVjK7xKBR2HmV0bJj6UcYct3-dXlp9gBHzbR1B00ziz6xxVosLg5aLArbNwjx7cCHmMtGc7gZXlavXGnv2Q");
		when(validationHelper.getTokenValidatedUserResponse(Mockito.any(),Mockito.any())).thenReturn(mosipUserDto);
		UserDetails authUserDetails = retrieveUser("110005",authToken);
		assertTrue(authUserDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_PROCESSOR")));
	}
	
	
	
}
