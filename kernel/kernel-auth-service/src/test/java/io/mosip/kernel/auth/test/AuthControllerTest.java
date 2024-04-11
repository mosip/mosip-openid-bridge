package io.mosip.kernel.auth.test;

import static org.mockito.Mockito.when;

import io.mosip.kernel.auth.controller.AuthController;
import io.mosip.kernel.core.authmanager.model.AuthNResponseDto;
import io.mosip.kernel.core.authmanager.model.LoginUser;
import io.mosip.kernel.openid.bridge.api.service.AuthService;

/**
 * //@author Ramadurai Pandian
 *
 */
//@RunWith(SpringRunner.class)
//@SpringBootTest(classes=AuthApp.class)
public class AuthControllerTest {

	// @Mock
	private AuthService authService;

	// @InjectMocks
	AuthController controller;

	private LoginUser loginUser;

	// @Before
	public void setUp() throws Exception {
		loginUser = new LoginUser();
		loginUser.setUserName("individual");
		loginUser.setPassword("individual");
		loginUser.setAppId("preregistration");

	}

	/**
	 * Test method for {//@link
	 * io.mosip.kernel.auth.controller.AuthController#authenticateUseridPwd(io.mosip.kernel.auth.entities.LoginUser,
	 * jakarta.servlet.http.HttpServletResponse)}. //@throws Exception
	 */
	// @Test
	public void testAuthenticateUseridPwd() throws Exception {
		AuthNResponseDto authNResponseDto = new AuthNResponseDto();
		when(authService.authenticateUser(loginUser)).thenReturn(authNResponseDto);
		String token = authNResponseDto.getToken();
	}

	/**
	 * Test method for {//@link
	 * io.mosip.kernel.auth.controller.AuthController#sendOTP(io.mosip.kernel.auth.entities.otp.OtpUser)}.
	 */
	// @Test
	public void testSendOTP() {

	}

	/**
	 * Test method for {//@link
	 * io.mosip.kernel.auth.controller.AuthController#userIdOTP(io.mosip.kernel.auth.entities.UserOtp,
	 * jakarta.servlet.http.HttpServletResponse)}.
	 */
	// @Test
	public void testUserIdOTP() {

	}

	/**
	 * Test method for {//@link
	 * io.mosip.kernel.auth.controller.AuthController#clientIdSecretKey(io.mosip.kernel.auth.entities.ClientSecret,
	 * jakarta.servlet.http.HttpServletResponse)}.
	 */
	// @Test
	public void testClientIdSecretKey() {

	}

	/**
	 * Test method for {//@link
	 * io.mosip.kernel.auth.controller.AuthController#validateToken(jakarta.servlet.http.HttpServletRequest,
	 * jakarta.servlet.http.HttpServletResponse)}.
	 */
	// @Test
	public void testValidateToken() {

	}

	/**
	 * Test method for {//@link
	 * io.mosip.kernel.auth.controller.AuthController#retryToken(jakarta.servlet.http.HttpServletRequest,
	 * jakarta.servlet.http.HttpServletResponse)}.
	 */
	// @Test
	public void testRetryToken() {

	}

	/**
	 * Test method for {//@link
	 * io.mosip.kernel.auth.controller.AuthController#invalidateToken(jakarta.servlet.http.HttpServletRequest,
	 * jakarta.servlet.http.HttpServletResponse)}.
	 */
	// @Test
	public void testInvalidateToken() {

	}

}
