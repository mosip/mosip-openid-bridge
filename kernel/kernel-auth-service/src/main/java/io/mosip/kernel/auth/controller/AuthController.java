package io.mosip.kernel.auth.controller;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.auth.defaultimpl.config.MosipEnvironment;
import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.constant.AuthErrorCode;
import io.mosip.kernel.auth.defaultimpl.dto.ClientSecretDto;
import io.mosip.kernel.auth.defaultimpl.dto.UserDetailsRequestDto;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.core.authmanager.model.AuthNResponse;
import io.mosip.kernel.core.authmanager.model.AuthNResponseDto;
import io.mosip.kernel.core.authmanager.model.AuthResponseDto;
import io.mosip.kernel.core.authmanager.model.ClientSecret;
import io.mosip.kernel.core.authmanager.model.IndividualIdDto;
import io.mosip.kernel.core.authmanager.model.LoginUserWithClientId;
import io.mosip.kernel.core.authmanager.model.MosipUserDto;
import io.mosip.kernel.core.authmanager.model.MosipUserListDto;
import io.mosip.kernel.core.authmanager.model.MosipUserSaltListDto;
import io.mosip.kernel.core.authmanager.model.MosipUserTokenDto;
import io.mosip.kernel.core.authmanager.model.OtpUser;
import io.mosip.kernel.core.authmanager.model.RIdDto;
import io.mosip.kernel.core.authmanager.model.RefreshTokenRequest;
import io.mosip.kernel.core.authmanager.model.RefreshTokenResponse;
import io.mosip.kernel.core.authmanager.model.RolesListDto;
import io.mosip.kernel.core.authmanager.model.UserOtp;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.exception.JsonMappingException;
import io.mosip.kernel.core.util.exception.JsonParseException;
import io.mosip.kernel.openid.bridge.api.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Controller APIs for Authentication and Authorization
 * 
 * @author Ramadurai Pandian
 * @since 1.0.0
 *
 */

@RestController
@Tag(name = "authmanager", description = "Operation related to Authentication and Authorization")
public class AuthController {

	private static Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

	@Value("${mosip.security.secure-cookie:false}")
	private boolean isSecureCookie;

	@Value("${mosip.kernel.auth-code-url-splitter:#URISPLITTER#}")
	private String urlSplitter;

	@Value("#{'${auth.allowed.urls}'.split(',')}")
	private List<String> allowedUrls;

	/**
	 * Autowired reference for {@link MosipEnvironment}
	 */

	@Autowired
	private MosipEnvironment mosipEnvironment;

	/**
	 * Autowired reference for {@link AuthService}
	 */

	@Autowired
	private AuthService authService;


	private Cookie createCookie(final String content, final int expirationTimeSeconds) {
		final Cookie cookie = new Cookie(mosipEnvironment.getAuthTokenHeader(), content);
		cookie.setMaxAge(expirationTimeSeconds);
		cookie.setHttpOnly(true);
		cookie.setSecure(isSecureCookie);
		cookie.setPath("/");
		return cookie;
	}

	/**
	 * API to send OTP
	 * 
	 * otpUser is of type {@link OtpUser}
	 * 
	 * @return ResponseEntity with OTP Sent message
	 */
	@ResponseFilter
	@PostMapping(value = "/authenticate/sendotp")
	@ResponseStatus(value = HttpStatus.OK)
	@Operation(summary = "Authenticate using OTP", description = "Authenticate using OTP", tags = { "authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthNResponse> sendOTP(@RequestBody @Valid RequestWrapper<OtpUser> otpUserDto)
			throws Exception {
		ResponseWrapper<AuthNResponse> responseWrapper = new ResponseWrapper<>();
		AuthNResponse authNResponse = null;
		AuthNResponseDto authResponseDto = authService.authenticateWithOtp(otpUserDto.getRequest());
		if (authResponseDto != null) {
			LOGGER.info("Send OTP for user " + otpUserDto.getRequest().getUserId() + " status "
					+ authResponseDto.getStatus());
			authNResponse = new AuthNResponse();
			authNResponse.setStatus(authResponseDto.getStatus());
			authNResponse.setMessage(authResponseDto.getMessage());
		} else {
			LOGGER.info("Send OTP failed for " + otpUserDto.getRequest().getUserId());
		}
		responseWrapper.setResponse(authNResponse);
		return responseWrapper;
	}

	/**
	 * API to validate OTP with user Id
	 * 
	 * userOtp is of type {@link UserOtp}
	 * 
	 * @return ResponseEntity with Cookie value with Auth token
	 */
	@ResponseFilter
	@PostMapping(value = "/authenticate/useridOTP")
	@Operation(summary = "API to validate OTP with user Id", description = "API to validate OTP with user Id", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthNResponse> userIdOTP(@RequestBody @Valid RequestWrapper<UserOtp> userOtpDto,
			HttpServletResponse res) throws Exception {
		ResponseWrapper<AuthNResponse> responseWrapper = new ResponseWrapper<>();
		AuthNResponse authNResponse = null;
		AuthNResponseDto authResponseDto = authService.authenticateUserWithOtp(userOtpDto.getRequest());
		if (authResponseDto != null && authResponseDto.getToken() != null) {
			LOGGER.info("useridOTP for user " + userOtpDto.getRequest().getUserId() + " status "
					+ authResponseDto.getStatus());
			Cookie cookie = createCookie(authResponseDto.getToken(), mosipEnvironment.getTokenExpiry());
			authNResponse = new AuthNResponse();
			res.addHeader(mosipEnvironment.getAuthTokenHeader(), authResponseDto.getToken());
			res.addCookie(cookie);
			authNResponse.setStatus(authResponseDto.getStatus());
			authNResponse.setMessage(authResponseDto.getMessage());
		} else if (authResponseDto != null) {
			LOGGER.info("useridOTP null for user " + userOtpDto.getRequest().getUserId() + " status "
					+ authResponseDto.getStatus());
			authNResponse = new AuthNResponse();
			authNResponse.setStatus(authResponseDto.getStatus());
			authNResponse.setMessage(
					authResponseDto.getMessage() != null ? authResponseDto.getMessage() : "Otp validation failed");
		} else {
			LOGGER.error("useridOTP auth response null for user " + userOtpDto.getRequest().getUserId());
		}
		responseWrapper.setResponse(authNResponse);
		return responseWrapper;
	}

	/**
	 * API to authenticate using clientId and secretKey
	 * 
	 * clientSecretDto is of type {@link ClientSecretDto}
	 * 
	 * @return ResponseEntity with Cookie value with Auth token
	 */
	@ResponseFilter
	@PostMapping(value = "/authenticate/clientidsecretkey")
	@Operation(summary = "API to authenticate using clientId and secretKey", description = "API to authenticate using clientId and secretKey", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthNResponse> clientIdSecretKey(
			@RequestBody @Valid RequestWrapper<ClientSecret> clientSecretDto, HttpServletResponse res)
			throws Exception {
		ResponseWrapper<AuthNResponse> responseWrapper = new ResponseWrapper<>();
		AuthNResponse authNResponse = null;
		AuthNResponseDto authResponseDto = authService.authenticateWithSecretKey(clientSecretDto.getRequest());
		if (authResponseDto != null) {
			LOGGER.info("clientidsecretkey for user " + clientSecretDto.getRequest().getClientId() + " status "
					+ authResponseDto.getStatus());
			Cookie cookie = createCookie(authResponseDto.getToken(), mosipEnvironment.getTokenExpiry());
			authNResponse = new AuthNResponse();
			res.addHeader(mosipEnvironment.getAuthTokenHeader(), authResponseDto.getToken());
			res.addCookie(cookie);
			authNResponse.setStatus(authResponseDto.getStatus());
			authNResponse.setMessage(authResponseDto.getMessage());
		} else {
			LOGGER.info("clientidsecretkey null for user " + clientSecretDto.getRequest().getClientId());
		}

		responseWrapper.setResponse(authNResponse);
		return responseWrapper;
	}

	/**
	 * API to validate token
	 * 
	 * 
	 * @return ResponseEntity with MosipUserDto
	 */
	@ResponseFilter
	@PostMapping(value = "/authorize/validateToken")
	@Operation(summary = "API to validate token", description = "API to validate token", tags = { "authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<MosipUserDto> validateToken(HttpServletRequest request, HttpServletResponse res)
			throws AuthManagerException, Exception {
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<>();
		String authToken = null;
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			throw new AuthManagerException(AuthErrorCode.COOKIE_NOTPRESENT_ERROR.getErrorCode(),
					AuthErrorCode.COOKIE_NOTPRESENT_ERROR.getErrorMessage());
		}
		MosipUserTokenDto mosipUserDtoToken = null;
		try {
			for (Cookie cookie : cookies) {
				if (cookie.getName().contains(AuthConstant.AUTH_COOOKIE_HEADER)) {
					authToken = cookie.getValue();
				}
			}
			if (authToken == null) {
				throw new AuthManagerException(AuthErrorCode.TOKEN_NOTPRESENT_ERROR.getErrorCode(),
						AuthErrorCode.TOKEN_NOTPRESENT_ERROR.getErrorMessage());
			}
			mosipUserDtoToken = authService.validateToken(authToken);
			if (mosipUserDtoToken != null) {
				LOGGER.info("token expiry time: " + mosipUserDtoToken.getExpTime() + " token payload: "
						+ mosipUserDtoToken.getToken().split("\\.")[1]);
				mosipUserDtoToken.setMessage(AuthConstant.TOKEN_SUCCESS_MESSAGE);
				Cookie cookie = createCookie(mosipUserDtoToken.getToken(), mosipEnvironment.getTokenExpiry());
				res.addCookie(cookie);
				responseWrapper.setResponse(mosipUserDtoToken.getMosipUserDto());
			}

		} catch (NonceExpiredException exp) {
			throw new AuthManagerException(AuthErrorCode.UNAUTHORIZED.getErrorCode(), exp.getMessage());
		}
		return responseWrapper;
	}

	/**
	 * API to validate token
	 * 
	 * 
	 * @return ResponseEntity with MosipUserDto
	 * @throws IOException
	 * @throws JsonMappingException
	 * @throws JsonParseException
	 */
	@ResponseFilter
	@GetMapping(value = "/authorize/admin/validateToken")
	@Operation(summary = "API to validate token", description = "API to validate token", tags = { "authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<MosipUserDto> validateAdminToken(HttpServletRequest request, HttpServletResponse res) {
		String authToken = null;
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			throw new AuthManagerException(AuthErrorCode.COOKIE_NOTPRESENT_ERROR.getErrorCode(),
					AuthErrorCode.COOKIE_NOTPRESENT_ERROR.getErrorMessage());
		}
		MosipUserDto mosipUserDto = null;
		try {
			for (Cookie cookie : cookies) {
				if (cookie.getName().contains(AuthConstant.AUTH_COOOKIE_HEADER)) {
					authToken = cookie.getValue();
				}
			}
			if (authToken == null) {
				throw new AuthManagerException(AuthErrorCode.TOKEN_NOTPRESENT_ERROR.getErrorCode(),
						AuthErrorCode.TOKEN_NOTPRESENT_ERROR.getErrorMessage());
			}

			mosipUserDto = authService.valdiateToken(authToken);
			LOGGER.debug(
					"validate admin token successful " + " token payload: " + mosipUserDto.getToken().split("\\.")[1]);
			Cookie cookie = createCookie(mosipUserDto.getToken(), mosipEnvironment.getTokenExpiry());
			res.addCookie(cookie);
		} catch (NonceExpiredException exp) {
			throw new AuthManagerException(AuthErrorCode.UNAUTHORIZED.getErrorCode(), exp.getMessage());
		}
		ResponseWrapper<MosipUserDto> responseWrapper = new ResponseWrapper<>();
		responseWrapper.setResponse(mosipUserDto);
		return responseWrapper;
	}

	/**
	 * API to retry token when auth token expires
	 * 
	 * 
	 * @return ResponseEntity with MosipUserDto
	 */
	@ResponseFilter
	@PostMapping(value = "/authorize/refreshToken/{appid}")
	@Operation(summary = "API to retry token when access token expires", description = "API to retry token when access token expires", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthNResponse> refreshToken(@PathVariable("appid") String appId,
			@RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest request, HttpServletResponse res)
			throws Exception {
		ResponseWrapper<AuthNResponse> responseWrapper = new ResponseWrapper<>();
		String refreshToken = null;
		Cookie[] cookies = request.getCookies();
		for (Cookie cookie : cookies) {
			if (cookie.getName().contains(AuthConstant.REFRESH_TOKEN)) {
				refreshToken = cookie.getValue();
				LOGGER.info("refresh token for app " + appId + " from cookie " + cookie.getName());
			}
		}
		Objects.requireNonNull(refreshToken, "No refresh token cookie found");
		RefreshTokenResponse mosipUserDtoToken = authService.refreshToken(appId, refreshToken, refreshTokenRequest);
		LOGGER.info("New refresh token obtained for app " + appId + " expires (access token) by "
				+ mosipUserDtoToken.getAccessTokenExpTime() + " refresh token expires in "
				+ mosipUserDtoToken.getRefreshTokenExpTime());
		Cookie cookie = createCookie(mosipUserDtoToken.getAccesstoken(), mosipEnvironment.getTokenExpiry());
		res.addCookie(cookie);
		Cookie refreshTokenCookie = new Cookie("refresh_token", mosipUserDtoToken.getRefreshToken());
		refreshTokenCookie.setHttpOnly(true);
		refreshTokenCookie.setSecure(isSecureCookie);
		res.addCookie(refreshTokenCookie);
		responseWrapper.setResponse(mosipUserDtoToken.getAuthNResponse());
		return responseWrapper;
	}

	/**
	 * API to invalidate token when both refresh and auth token expires
	 * 
	 * 
	 * @return ResponseEntity with MosipUserDto
	 */
	@ResponseFilter
	@PostMapping(value = "/authorize/invalidateToken")
	@Operation(summary = "API to invalidate token when both refresh and auth token expires", description = "API to invalidate token when both refresh and auth token expires", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthNResponse> invalidateToken(HttpServletRequest request, HttpServletResponse res)
			throws Exception {
		ResponseWrapper<AuthNResponse> responseWrapper = new ResponseWrapper<>();
		String authToken = null;
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			throw new AuthManagerException(AuthErrorCode.COOKIE_NOTPRESENT_ERROR.getErrorCode(),
					AuthErrorCode.COOKIE_NOTPRESENT_ERROR.getErrorMessage());
		}
		for (Cookie cookie : cookies) {
			if (cookie.getName().contains(AuthConstant.AUTH_COOOKIE_HEADER)) {
				authToken = cookie.getValue();
				LOGGER.info("Attempt to invalidate the token from cookie  " + cookie.getName());
			}
		}
		if (authToken == null) {
			throw new AuthManagerException(AuthErrorCode.TOKEN_NOTPRESENT_ERROR.getErrorCode(),
					AuthErrorCode.TOKEN_NOTPRESENT_ERROR.getErrorMessage());
		}
		AuthNResponse authNResponse = authService.invalidateToken(authToken);
		LOGGER.info("Invalidated the token  " + authToken);
		responseWrapper.setResponse(authNResponse);
		return responseWrapper;
	}

	@ResponseFilter
	@GetMapping(value = "/roles/{appid}")
	@Operation(summary = "API to get all roles", description = "API to get all roles", tags = { "authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<RolesListDto> getAllRoles(@PathVariable("appid") String appId) throws Exception {
		ResponseWrapper<RolesListDto> responseWrapper = new ResponseWrapper<>();
		RolesListDto rolesListDto = authService.getAllRoles(appId);
		LOGGER.info("Get roles for " + appId + ". Total roles:  " + rolesListDto.getRoles().size());
		responseWrapper.setResponse(rolesListDto);
		return responseWrapper;
	}

	@ResponseFilter
	@PostMapping(value = "/userdetails/{appid}")
	@Operation(summary = "API to get list of users for a module", description = "API to get list of users for a module", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<MosipUserListDto> getListOfUsersDetails(
			@RequestBody RequestWrapper<UserDetailsRequestDto> userDetails, @PathVariable("appid") String appId)
			throws Exception {
		ResponseWrapper<MosipUserListDto> responseWrapper = new ResponseWrapper<>();
		MosipUserListDto mosipUsers = authService.getListOfUsersDetails(userDetails.getRequest().getUserDetails(),
				appId);
		LOGGER.info("Get userdetails for " + appId + ". Total users:  " + mosipUsers.getMosipUserDtoList().size());
		responseWrapper.setResponse(mosipUsers);
		return responseWrapper;
	}

	@ResponseFilter
	@PostMapping(value = "/usersaltdetails/{appid}")
	@Operation(summary = "API to get list of users for a module with salt", description = "API to get list of users for a module with salt", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<MosipUserSaltListDto> getUserDetailsWithSalt(
			@RequestBody RequestWrapper<UserDetailsRequestDto> userDetails, @PathVariable("appid") String appId)
			throws Exception {
		ResponseWrapper<MosipUserSaltListDto> responseWrapper = new ResponseWrapper<>();
		MosipUserSaltListDto mosipUsers = authService
				.getAllUserDetailsWithSalt(userDetails.getRequest().getUserDetails(), appId);
		LOGGER.info("Get usersaltdetails for " + appId + ". Total user salts:  "
				+ mosipUsers.getMosipUserSaltList().size());
		responseWrapper.setResponse(mosipUsers);
		return responseWrapper;
	}

	/**
	 * This API will fetch RID based on appId and userId.
	 * 
	 * @param appId  - application Id
	 * @param userId - user Id
	 * @return {@link RIdDto}
	 * @throws Exception
	 */
	@ResponseFilter
	@GetMapping(value = "rid/{appid}/{userid}")
	@Operation(summary = "API to get rid", description = "API to get rid from userid", tags = { "authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<RIdDto> getRId(@PathVariable("appid") String appId, @PathVariable("userid") String userId)
			throws Exception {
		ResponseWrapper<RIdDto> responseWrapper = new ResponseWrapper<>();
		RIdDto rIdDto = authService.getRidBasedOnUid(userId, appId);
		LOGGER.info("Get rid for " + appId + ". Rid:  " + rIdDto.getRId());
		responseWrapper.setResponse(rIdDto);
		return responseWrapper;
	}

	/**
	 * 
	 * @param req - {@link HttpServletRequest}
	 * @param res - {@link HttpServletResponse}
	 * @return {@link ResponseWrapper}
	 */
	@ResponseFilter
	@DeleteMapping(value = "/logout/user")
	@Operation(summary = "Logout a user", description = "ends users session", tags = { "authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthResponseDto> logoutUser(
			@CookieValue(value = "Authorization", required = false) String token, HttpServletResponse res) {
		AuthResponseDto authResponseDto = authService.logoutUser(token);
		LOGGER.info("logout user " + token + ". Response " + authResponseDto.getStatus());
		ResponseWrapper<AuthResponseDto> responseWrapper = new ResponseWrapper<>();
		responseWrapper.setResponse(authResponseDto);
		return responseWrapper;
	}

	/**
	 * Erases Cookie from browser
	 * 
	 * @param cookie - {@link Cookie}
	 */
	private void removeCookie(Cookie cookie) {
		cookie.setValue("");
		cookie.setPath("/");
		cookie.setMaxAge(0);
	}

	/**
	 * Internal API used by syncdata delegate API
	 * 
	 * @param request
	 * @param res
	 * @return
	 * @throws Exception
	 */
	@ResponseFilter
	@PostMapping(value = "/authenticate/internal/useridPwd")
	@Operation(summary = "Internal API used by syncdata delegate API to authenticate", description = "Internal API used by syncdata delegate API to authenticate", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthNResponseDto> getAllAuthTokens(
			@RequestBody @Valid RequestWrapper<LoginUserWithClientId> request, HttpServletResponse res)
			throws Exception {
		ResponseWrapper<AuthNResponseDto> responseWrapper = new ResponseWrapper<>();
		AuthNResponseDto authResponseDto = authService.authenticateUser(request.getRequest());
		responseWrapper.setResponse(authResponseDto);
		return responseWrapper;
	}

	/**
	 * Internal API used by syncdata delegate API
	 * 
	 * @param request
	 * @param res
	 * @return
	 * @throws Exception
	 */
	@ResponseFilter
	@PostMapping(value = "/authenticate/internal/userotp")
	@Operation(summary = "Internal API used by syncdata delegate API to authenticate using otp", description = "Internal API used by syncdata delegate API to authenticate using otp", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthNResponseDto> getAllAuthTokensForOTP(@RequestBody @Valid RequestWrapper<UserOtp> request,
			HttpServletResponse res) throws Exception {
		ResponseWrapper<AuthNResponseDto> responseWrapper = new ResponseWrapper<>();
		AuthNResponseDto authResponseDto = authService.authenticateUserWithOtp(request.getRequest());
		responseWrapper.setResponse(authResponseDto);
		return responseWrapper;
	}

	/**
	 * Internal API used by syncdata delegate API
	 * 
	 * @param appId
	 * @param refreshTokenRequest
	 * @param request
	 * @param res
	 * @return
	 * @throws Exception
	 */
	@ResponseFilter
	@PostMapping(value = "/authorize/internal/refreshToken/{appid}")
	@Operation(summary = "Internal API used by syncdata delegate API to refreah token", description = "Internal API used by syncdata delegate API to refresh token", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<AuthNResponseDto> refreshAuthToken(@PathVariable("appid") String appId,
			@RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest request, HttpServletResponse res)
			throws Exception {
		ResponseWrapper<AuthNResponseDto> responseWrapper = new ResponseWrapper<>();
		String refreshToken = null;
		Cookie[] cookies = request.getCookies();
		for (Cookie cookie : cookies) {
			if (cookie.getName().contains(AuthConstant.REFRESH_TOKEN)) {
				refreshToken = cookie.getValue();
				LOGGER.info("refresh token for app " + appId + " from cookie " + cookie.getName());
			}
		}
		Objects.requireNonNull(refreshToken, "No refresh token cookie found");
		RefreshTokenResponse mosipUserDtoToken = authService.refreshToken(appId, refreshToken, refreshTokenRequest);
		AuthNResponseDto authNResponseDto = new AuthNResponseDto();
		authNResponseDto.setToken(mosipUserDtoToken.getAccesstoken());
		authNResponseDto.setRefreshToken(mosipUserDtoToken.getRefreshToken());
		authNResponseDto.setExpiryTime(Long.parseLong(mosipUserDtoToken.getAccessTokenExpTime()));
		authNResponseDto.setRefreshExpiryTime(Long.parseLong(mosipUserDtoToken.getRefreshTokenExpTime()));
		responseWrapper.setResponse(authNResponseDto);
		return responseWrapper;
	}

	/**
	 * This API will fetch RID based on appId and userId.
	 * 
	 * @param appId  - application Id
	 * @param userId - user Id
	 * @return {@link IndividualIdDto}
	 * @throws Exception
	 */
	@ResponseFilter
	@GetMapping(value = "individualId/{appid}/{userid}")
	@Operation(summary = "This API will fetch IndividualId based on appId and userId", description = "This API will fetch IndividualId based on appId and userId", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<IndividualIdDto> getIndividualId(@PathVariable("appid") String appId,
			@PathVariable("userid") String userId) {
		ResponseWrapper<IndividualIdDto> responseWrapper = new ResponseWrapper<>();
		IndividualIdDto individualIdDto = authService.getIndividualIdBasedOnUserID(userId, appId);
		responseWrapper.setResponse(individualIdDto);
		return responseWrapper;
	}

	/**
	 * This API will fetch all users based on appId and roles for role bases search
	 * only pagination will work. with out role can be searched by all.
	 * email,firstName,lastName and userName
	 * 
	 * @param appId
	 * @param roleName
	 * @return
	 * @throws Exception
	 */
	@ResponseFilter
	@GetMapping(value = "/userdetails/{appid}")
	@Operation(summary = "This API will fetch all users based on appId and roles", description = "This API will fetch all users based on appId and roles for role bases search only pagination will work,Without role can be searched by all,email,firstName,lastName and userName", tags = {
			"authmanager" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<MosipUserListDto> getUsersDetails(@PathVariable("appid") String appId,
			@RequestParam(required = false, name = "roleName") String roleName,
			@RequestParam(defaultValue = "0", required = false, name = "pageStart") int pageStart,
			@RequestParam(defaultValue = "0", required = false, name = "pageFetch") int pageFetch,
			@RequestParam(required = false, name = "email") String email,
			@RequestParam(required = false, name = "firstName") String firstName,
			@RequestParam(required = false, name = "lastName") String lastName,
			@RequestParam(required = false, name = "userName") String userName,
			@RequestParam(required = false, name = "search") String search) throws Exception {
		ResponseWrapper<MosipUserListDto> responseWrapper = new ResponseWrapper<>();
		MosipUserListDto mosipUsers = authService.getListOfUsersDetails(appId, roleName, pageStart, pageFetch, email,
				firstName, lastName, userName, search);
		LOGGER.info("Get userdetails for " + appId + ". Total users:  " + mosipUsers.getMosipUserDtoList().size());
		responseWrapper.setResponse(mosipUsers);
		return responseWrapper;
	}
}
