/**
 * 
 */
package io.mosip.kernel.auth.defaultadapter.filter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
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
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.EmptyCheckUtils;

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

	@Autowired
	private Environment environment;

	@SuppressWarnings("unchecked")
	public AuthFilter(RequestMatcher requiresAuthenticationRequestMatcher,
			NoAuthenticationEndPoint noAuthenticationEndPoint, Environment environment) {
		super(requiresAuthenticationRequestMatcher);
		this.noAuthenticationEndPoint = noAuthenticationEndPoint;
		String applName = getApplicationName(environment);
		allowedHttpMethods = (List<String>) environment.getProperty(
				"mosip.service.exclude.auth.allowed.method." + applName, List.class, environment.getProperty(
						"mosip.service.exclude.auth.allowed.method", List.class, Collections.singletonList("GET")));
		mapper = JsonMapper.builder().addModule(new AfterburnerModule()).build();
		mapper.registerModule(new JavaTimeModule());
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		// To check the global end-points
		if (isPresent(request, noAuthenticationEndPoint.getGlobal().getEndPoints())) {
			return false;
		}
		// As the request not a part of the global end-points, check in master data
		// end-points
		boolean isValid = isValid(noAuthenticationEndPoint);
		if (isValid) {
			if (request.getServletContext().getContextPath()
					.equalsIgnoreCase(noAuthenticationEndPoint.getServiceContext())) {
				return (allowedHttpMethods.contains(request.getMethod())
						&& isPresent(request, noAuthenticationEndPoint.getService().getEndPoints())) ? false : true;
			}
		}
		return true;
	}

	private boolean isPresent(HttpServletRequest request, List<String> endPoints) {
		return endPoints.stream().filter(pattern -> new AntPathRequestMatcher(pattern).matches(request)).findFirst()
				.isPresent();
	}

	private boolean isValid(NoAuthenticationEndPoint noAuthenticationEndPoint) {
		if (noAuthenticationEndPoint.getServiceContext() == null
				|| noAuthenticationEndPoint.getServiceContext().isEmpty())
			return false;
		if (noAuthenticationEndPoint.getService() == null
				&& noAuthenticationEndPoint.getService().getEndPoints() == null
				&& noAuthenticationEndPoint.getService().getEndPoints().isEmpty())
			return false;
		return true;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse)
			throws AuthenticationException, JsonProcessingException, IOException {
		String token = null;
		String idToken = null;
		Cookie[] cookies = null;
		try {
			cookies = httpServletRequest.getCookies();
			if (cookies != null) {
				for (Cookie cookie : cookies) {
					if (cookie.getName().contains(AuthAdapterConstant.AUTH_REQUEST_COOOKIE_HEADER)) {
						LOGGER.debug("extract token from cookie named " + cookie.getName());
						token = cookie.getValue();
					} else {
						String idTokenName=this.environment.getProperty(AuthAdapterConstant.ID_TOKEN);
						if(idTokenName!=null){
							if(cookie.getName().contains(idTokenName)){
								LOGGER.debug("extract token from cookie named " + cookie.getName());
								idToken = cookie.getValue();
							}
						}
					}
				}
			}
		} catch (Exception e) {
			LOGGER.debug("extract token from cookie failed for request " + httpServletRequest.getRequestURI());
		}

		if (token == null) {
			ResponseWrapper<ServiceError> errorResponse = setErrors(httpServletRequest);
			ServiceError error = new ServiceError(AuthAdapterErrorCode.UNAUTHORIZED.getErrorCode(),
					"Authentication Failed");
			errorResponse.getErrors().add(error);
			httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
			httpServletResponse.setContentType("application/json");
			httpServletResponse.setCharacterEncoding("UTF-8");
			httpServletResponse.getWriter().write(convertObjectToJson(errorResponse));
			LOGGER.error("\n\n Exception : Authorization token not present > " + httpServletRequest.getRequestURL()
					+ "\n\n");
			return null;
		}
		AuthToken authToken = null;
		if(idToken==null){
			 authToken = new AuthToken(token);
		} else{
			authToken = new AuthToken(token, idToken);
		}

		LOGGER.debug("Extracted auth token for request " + httpServletRequest.getRequestURL());
		return getAuthenticationManager().authenticate(authToken);
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
		AuthManagerException exception = (AuthManagerException) failed;
		ResponseWrapper<ServiceError> errorResponse = setErrors(request);
		if (exception.getList().size() != 0) {
			errorResponse.getErrors().addAll(exception.getList());
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
		if (object == null) {
			return null;
		}

		return mapper.writeValueAsString(object);
	}

	private String getApplicationName(Environment environment) {
		String appNames = environment.getProperty("spring.application.name");
		if (!EmptyCheckUtils.isNullEmpty(appNames)) {
			List<String> appNamesList = Stream.of(appNames.split(",")).collect(Collectors.toList());
			return appNamesList.get(0);
		} else {
			throw new RuntimeException("property spring.application.name not found");
		}
	}

}
