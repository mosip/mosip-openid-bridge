/**
 * 
 */
package io.mosip.kernel.auth.defaultadapter.filter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.ContentCachingRequestWrapper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;

import io.mosip.kernel.auth.defaultadapter.config.NoAuthenticationEndPoint;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultadapter.model.AuthToken;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.openid.bridge.api.constants.Constants;
import io.mosip.kernel.openid.bridge.api.constants.Errors;
import io.mosip.kernel.openid.bridge.api.exception.ClientException;
import io.mosip.kernel.openid.bridge.api.utils.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * @author Ramadurai Saravana Pandian
 * @author Raj Jha
 * @author Urvil Joshi
 * @author GOVINDARAJ VELU -> End-points modification
 *
 */
public class AuthFilter extends AbstractAuthenticationProcessingFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthFilter.class);

	private NoAuthenticationEndPoint noAuthenticationEndPoint;

	private ObjectMapper mapper;
	private List<String> allowedHttpMethods;

	@Value("${auth.validate.id-token:false}")
	private boolean validateIdToken;
	
	@Value("${auth.handle.ctk.flow:false}")
	private boolean flagToHandleCtkFlow;
	
	@Value("${mosip.compliance.toolkit.saveDataShareToken.url:}")
	private String ctkSaveUrl;
	
	@Value("${mosip.compliance.toolkit.invalidateDataShareToken.url:}")
	private String ctkInvalidateUrl;
	
	@Value("${mosip.compliance.toolkit.invalidateDataShareToken.testCaseId:}")
	private String ctkInvalidateTestCaseId;
	
	@Autowired
	private Environment environment;

	@Value("${mosip.auth.rest.connectTimeout:200}")
	private int connectTimeoutMs;

	@Value("${mosip.auth.rest.readTimeout:500}")
	private int readTimeoutMs;

	private final RestTemplate restTemplate;

	private static final String ACTUATOR_PREFIX = "/actuator";
	private static final String OPTIONS = "OPTIONS";

	private final List<AntPathRequestMatcher> globalMatchers;
	private final List<AntPathRequestMatcher> serviceMatchers;

	@SuppressWarnings("unchecked")
	public AuthFilter(RequestMatcher requiresAuthenticationRequestMatcher,
			NoAuthenticationEndPoint noAuthenticationEndPoint, Environment environment) {
		super(requiresAuthenticationRequestMatcher);
		this.noAuthenticationEndPoint = noAuthenticationEndPoint;

		String applName = getApplicationName(environment);
		this.allowedHttpMethods = (List<String>) environment.getProperty(
				"mosip.service.exclude.auth.allowed.method." + applName, List.class, environment.getProperty(
						"mosip.service.exclude.auth.allowed.method", List.class, Collections.singletonList("GET")));

		this.mapper = JsonMapper.builder().addModule(new AfterburnerModule()).build();
		this.mapper.registerModule(new JavaTimeModule());

		// Precompile patterns once
		this.globalMatchers = safeList(noAuthenticationEndPoint.getGlobal() != null
				? noAuthenticationEndPoint.getGlobal().getEndPoints() : null)
				.stream().map(AntPathRequestMatcher::new).collect(Collectors.toList());

		this.serviceMatchers = (noAuthenticationEndPoint.getService() != null)
				? safeList(noAuthenticationEndPoint.getService().getEndPoints())
				.stream().map(AntPathRequestMatcher::new).collect(Collectors.toList())
				: Collections.emptyList();

		// RestTemplate with timeouts
		SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
		factory.setConnectTimeout(connectTimeoutMs);
		factory.setReadTimeout(readTimeoutMs);
		this.restTemplate = new RestTemplate(factory);
	}

	private static List<String> safeList(List<String> l) {
		return (l == null) ? Collections.emptyList() : l;
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		// 1) Cheap short-circuits
		if (OPTIONS.equals(request.getMethod())) return false;

		final String ctx = request.getContextPath() == null ? "" : request.getContextPath();
		final String uri = request.getRequestURI();

		// Bypass actuator endpoints unconditionally
		if (uri.startsWith(ctx + ACTUATOR_PREFIX)) return false;

		// 2) Global no-auth endpoints
		if (matchesAny(request, globalMatchers)) return false;

		// 3) Service-scoped no-auth endpoints (method + path + context)
		if (isValid(noAuthenticationEndPoint)) {
			String svcCtx = noAuthenticationEndPoint.getServiceContext();
			if (svcCtx != null && request.getServletContext().getContextPath().equalsIgnoreCase(svcCtx)) {
				if (allowedHttpMethods.contains(request.getMethod()) && matchesAny(request, serviceMatchers)) {
					return false;
				}
			}
		}

		// 4) Otherwise, authentication required
		return true;
	}

	private static boolean matchesAny(HttpServletRequest req, List<AntPathRequestMatcher> matchers) {
		for (AntPathRequestMatcher m : matchers) {
			if (m.matches(req)) return true;
		}
		return false;
	}

	private boolean isPresent(HttpServletRequest request, List<String> endPoints) {
		return endPoints.stream().filter(pattern -> new AntPathRequestMatcher(pattern).matches(request)).findFirst()
				.isPresent();
	}

	private boolean isValid(NoAuthenticationEndPoint n) {
		if (n == null) return false;
		if (n.getServiceContext() == null || n.getServiceContext().isEmpty()) return false;
		if (n.getService() == null) return false;
		List<String> eps = n.getService().getEndPoints();
		return eps != null && !eps.isEmpty();
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse)
			throws AuthenticationException, IOException, ServletException {
		String token = null;
		String idToken = null;
		Cookie[] cookies = null;
		String authTokenSub = null;
		String idTokenSub = null;
		boolean isIdTokenAvailable = false;
		try {
			cookies = httpServletRequest.getCookies();
			if (cookies != null) {
				for (Cookie cookie : cookies) {
					String name = cookie.getName();
					String val = cookie.getValue();

					if (name != null && name.contains(AuthAdapterConstant.AUTH_REQUEST_COOOKIE_HEADER)) {
						LOGGER.debug("extract token from cookie named " + name);
						token = val;
						if (validateIdToken) {
							authTokenSub = JWTUtils.
									getSubClaimValueFromToken(val,
											this.environment.getProperty(Constants.TOKEN_SUBJECT_CLAIM_NAME));
						}
					} else {
						String idTokenName = this.environment.getProperty(AuthAdapterConstant.ID_TOKEN);
						if (idTokenName != null) {
							if (name != null && name.contains(idTokenName)) {
								LOGGER.debug("extract token from cookie named " + name);
								idToken = val;
								if (validateIdToken) {
									if (idToken == null || idToken.isEmpty()) {
										throw new ClientException(Errors.TOKEN_NOTPRESENT_ERROR.getErrorCode(),
												Errors.TOKEN_NOTPRESENT_ERROR.getErrorMessage() + ": " + idTokenName);
									}
									isIdTokenAvailable = true;
									idTokenSub = JWTUtils.
											getSubClaimValueFromToken(idToken,
													this.environment.getProperty(Constants.TOKEN_SUBJECT_CLAIM_NAME));
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			LOGGER.debug("extract token from cookie failed for request " + httpServletRequest.getRequestURI());
		}

		if (validateIdToken && !isIdTokenAvailable) {
			LOGGER.error("Id token not available.");
			return sendAuthenticationFailure(httpServletRequest, httpServletResponse);
		}

		if (validateIdToken && (idTokenSub == null || !idTokenSub.equalsIgnoreCase(authTokenSub))) {
			LOGGER.error("Sub of Id token and auth token didn't match.");
			return sendAuthenticationFailure(httpServletRequest, httpServletResponse);
		}

		if (token == null) {
			LOGGER.error("\n\n Exception : Authorization token not present > " + httpServletRequest.getRequestURL()
					+ "\n\n");
			return sendAuthenticationFailure(httpServletRequest, httpServletResponse);
		}

		final AuthToken authToken = (idToken == null) ? new AuthToken(token) : new AuthToken(token, idToken);
		LOGGER.debug("Extracted auth token for request " + httpServletRequest.getRequestURL());
		Authentication auth = getAuthenticationManager().authenticate(authToken);
		/*
		 * This is custom  fail-safe handling added only for Compliance Toolkit, to enable ABIS
		 * data share testing.
		 */
		if (auth != null && auth.isAuthenticated() && flagToHandleCtkFlow) {
			handleCtkTokenFlow(httpServletRequest, token);
		}
		return auth;
	}

	private Authentication sendAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
		ResponseWrapper<ServiceError> errorResponse = setErrors(httpServletRequest);
		ServiceError error = new ServiceError(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(),
				"Authentication Failed");
		errorResponse.getErrors().add(error);
		httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
		httpServletResponse.setContentType("application/json");
		httpServletResponse.setCharacterEncoding("UTF-8");
		httpServletResponse.getWriter().write(convertObjectToJson(errorResponse));
		return null;
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
		chain.doFilter(request, response);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
											  AuthenticationException failed) throws IOException, ServletException {
		AuthManagerException ex = (failed instanceof AuthManagerException) ? (AuthManagerException) failed : null;
		ResponseWrapper<ServiceError> errorResponse = setErrors(request);
		if (ex != null && ex.getList() != null && !ex.getList().isEmpty()) {
			errorResponse.getErrors().addAll(ex.getList());
		} else {
			ServiceError error = new ServiceError(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(),
					"Authentication Failed");
			errorResponse.getErrors().add(error);
		}
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		ExceptionUtils.logRootCause(failed);
		response.getWriter().write(convertObjectToJson(errorResponse));
	}

	private ResponseWrapper<ServiceError> setErrors(HttpServletRequest httpServletRequest) throws IOException {
		ResponseWrapper<ServiceError> responseWrapper = new ResponseWrapper<>();
		responseWrapper.setResponsetime(LocalDateTime.now(ZoneId.of("UTC")));
		String requestBody = null;
		if (httpServletRequest instanceof ContentCachingRequestWrapper) {
			requestBody = new String(((ContentCachingRequestWrapper) httpServletRequest).getContentAsByteArray());
		}
		if (EmptyCheckUtils.isNullEmpty(requestBody)) {
			return responseWrapper;
		}

		JsonNode reqNode = mapper.readTree(requestBody);
		responseWrapper.setId(reqNode.path("id").asText());
		responseWrapper.setVersion(reqNode.path("version").asText());
		return responseWrapper;
	}

	private String convertObjectToJson(Object object) throws JsonProcessingException {
		return (object == null) ? null : mapper.writeValueAsString(object);
	}

	@SuppressWarnings("java:S2259") // added suppress for sonarcloud. Null check is performed at line # 211
	private String getApplicationName(Environment environment) {
		String appNames = environment.getProperty("spring.application.name");
		if (appNames != null && !EmptyCheckUtils.isNullEmpty(appNames)) {
			List<String> appNamesList = Stream.of(appNames.split(",")).collect(Collectors.toList());
			return appNamesList.get(0);
		}
		throw new RuntimeException("property spring.application.name not found");
	}

	/**
	 * This is custom fail-safe handling added only for Compliance Toolkit, to
	 * enable ABIS data share testing.
	 */
	private void handleCtkTokenFlow(HttpServletRequest httpServletRequest, String token) {
		String ctkTestCaseId = null;
		String ctkTestRunId = null;
		Map<String, String[]> requestParams = httpServletRequest.getParameterMap();
		String[] testCaseIdArr = requestParams.get(AuthAdapterConstant.CTK_TEST_CASE_ID);
		if (testCaseIdArr != null && testCaseIdArr.length > 0) {
			ctkTestCaseId = testCaseIdArr[0];
			LOGGER.debug("Recvd ctkTestCaseId {}", sanitize(ctkTestCaseId));
		}
		String[] testRunIdArr = requestParams.get(AuthAdapterConstant.CTK_TEST_RUN_ID);
		if (testRunIdArr != null && testRunIdArr.length > 0) {
			ctkTestRunId = testRunIdArr[0];
			LOGGER.debug("Recvd ctkTestRunId {}", sanitize(ctkTestRunId));
		}
		if (ctkTestCaseId != null && ctkTestRunId != null) {
			if (ctkSaveUrl == null) {
				LOGGER.info("Invalid value for property 'mosip.compliance.toolkit.saveDataShareToken.url' {}", ctkSaveUrl);
				return;
			}
			if (ctkInvalidateUrl == null && ctkInvalidateTestCaseId != null) {
				LOGGER.info("Invalid value for property 'mosip.compliance.toolkit.invalidateDataShareToken.url' {}", ctkInvalidateUrl);
				return;
			}
			// get the partnerId from URL
			String path = httpServletRequest.getPathInfo();
			String[] splits = path.split("/");
			String partnerId = null;
			if (splits.length > 2) {
				partnerId = splits[splits.length - 2];
			}
			if (partnerId == null) {
				LOGGER.info("Invalid DataShare URL {}", httpServletRequest.getRequestURI());
				return;
			}
			LOGGER.debug("Recvd partnerId {}", sanitize(partnerId));
			// add the token first
			HttpHeaders headers = new HttpHeaders();
			headers.add(AuthAdapterConstant.AUTH_HEADER_COOKIE, AuthAdapterConstant.AUTH_HEADER + token);
			headers.setContentType(MediaType.APPLICATION_JSON);
			// create request
			Map<String, String> valueMap = new HashMap<String, String>();
			valueMap.put(AuthAdapterConstant.PARTNER_ID, partnerId);
			valueMap.put(AuthAdapterConstant.CTK_TEST_CASE_ID, ctkTestCaseId);
			valueMap.put(AuthAdapterConstant.CTK_TEST_RUN_ID, ctkTestRunId);
			RequestWrapper<Object> requestWrapper = new RequestWrapper<>();
			requestWrapper.setId("mosip.toolkit.abis.datashare.token");
			requestWrapper.setVersion("1.0");
			requestWrapper.setRequesttime(LocalDateTime.now());
			requestWrapper.setRequest(valueMap);
			
			ResponseEntity<ResponseWrapper<String>> responseEntity = null;
			try {
				HttpEntity<RequestWrapper<Object>> requestEntity = new HttpEntity<>(requestWrapper, headers);
				String tokenUrl = ctkSaveUrl;
				if (ctkInvalidateTestCaseId != null && ctkInvalidateTestCaseId.equals(ctkTestCaseId)) {
					tokenUrl = ctkInvalidateUrl;
				}
				LOGGER.debug("Calling Compliance Toolkit URL: " + tokenUrl);
				responseEntity = restTemplate.exchange(tokenUrl, HttpMethod.POST, requestEntity,
						new ParameterizedTypeReference<ResponseWrapper<String>>() {
						});
				ResponseWrapper<String> body = responseEntity.getBody();
				if (body != null) {
					LOGGER.debug("Response from Compliance Toolkit: " + body.getResponse());
					return;
				}
				LOGGER.debug("Response from Compliance Toolkit response body is null");
			} catch (Exception e) {
				// This is FailSafe, so just log the err
				LOGGER.error("error connecting to compliance toolkit: " + e.getStackTrace(), e);
			}
		}
	}

	private String sanitize(String msg) {
		return msg.replaceAll("[\n\r]", " ");
	}


}
