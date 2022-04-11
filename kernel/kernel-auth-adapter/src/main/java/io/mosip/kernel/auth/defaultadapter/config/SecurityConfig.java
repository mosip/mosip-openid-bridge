package io.mosip.kernel.auth.defaultadapter.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.mosip.kernel.auth.defaultadapter.filter.AuthFilter;
import io.mosip.kernel.auth.defaultadapter.filter.CSRFFilter;
import io.mosip.kernel.auth.defaultadapter.filter.CorsFilter;
import io.mosip.kernel.auth.defaultadapter.handler.AuthHandler;
import io.mosip.kernel.auth.defaultadapter.handler.AuthSuccessHandler;
import io.mosip.kernel.core.util.EmptyCheckUtils;

/**
 * Holds the main configuration for authentication and authorization using
 * spring security.
 *
 * Inclusions: 1. AuthenticationManager bean configuration: a. This is assigned
 * an authProvider that we implemented. This option can include multiple auth
 * providers if necessary based on the requirement. b. RETURNS an instance of
 * the ProviderManager. 2. AuthFilter bean configuration: a. This extends
 * AbstractAuthenticationProcessingFilter. b. Instance of the AuthFilter is
 * created. c. This filter comes in line after the AuthHeadersFilter. d. Binds
 * the AuthenticationManager instance created with the filter. e. Binds the
 * AuthSuccessHandler created with the filter. f. RETURNS an instance of the
 * AuthFilter. 3. RestTemplate bean configuration: a. Binds the
 * ClientInterceptor instance with the RestTemplate instance created. b. RETURNS
 * an instance of the RestTemplate. 4. Secures endpoints using antMatchers and
 * adds filters in a sequence for execution.
 *
 * @author Sabbu Uday Kumar
 * @author Ramadurai Saravana Pandian
 * @author Raj Jha
 * @author Urvil Joshi
 * 
 * @since 1.0.0
 **/
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(2)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

	@Value("${mosip.kernel.csrf_ignore.url:}")
	private String[] csrfIgnoreUrls;

	@Value("${mosip.security.csrf-enable:false}")
	private boolean isCSRFEnable;

	@Value("${mosip.security.cors-enable:false}")
	private boolean isCORSEnable;

	@Value("${mosip.security.origins:localhost:8080}")
	private String origins;

	@Autowired
	private ApplicationContext applicationContext;

	@Autowired
	private AuthHandler authProvider;

	@Autowired
	private Environment environment;

	/**
	 * It's inject the end-points.
	 */
	@Autowired
	private NoAuthenticationEndPoint noAuthenticationEndPoint;

	// @ConditionalOnMissingBean(AuthenticationManager.class)
	@Bean
	@SuppressWarnings("unchecked")
	public AuthenticationManager authenticationManager() {
		List<AuthenticationProvider> authProviders = new ArrayList<>();
		String applName = getApplicationName();
		List<String> otherAuthProviders = (List<String>) environment.getProperty(
				"mosip.security.authentication.provider.beans.list." + applName, List.class, Collections.EMPTY_LIST);
		otherAuthProviders.stream().forEach(beanName -> {
			try {
				if (Objects.nonNull(beanName) && !beanName.equals("")) {
					authProviders
							.add(applicationContext.getBean(beanName, AbstractUserDetailsAuthenticationProvider.class));
					LOGGER.info("Added Custom Auth Provider Bean in the list {} ", beanName);
				}
			} catch (Exception ex) {
				LOGGER.error("Error Adding bean to providers list: " + beanName, ex);
			}
		});
		authProviders.add(authProvider);
		return new ProviderManager(authProviders);
	}

	// @ConditionalOnMissingBean(AbstractAuthenticationProcessingFilter.class)
	@Bean
	public AbstractAuthenticationProcessingFilter authFilter() {
		RequestMatcher requestMatcher = new AntPathRequestMatcher("*");
		AuthFilter filter = new AuthFilter(requestMatcher, noAuthenticationEndPoint, environment);
		filter.setAuthenticationManager(authenticationManager());
		filter.setAuthenticationSuccessHandler(new AuthSuccessHandler());
		return filter;
	}

	@Bean
	public FilterRegistrationBean<AbstractAuthenticationProcessingFilter> registration(
			AbstractAuthenticationProcessingFilter filter) {
		FilterRegistrationBean<AbstractAuthenticationProcessingFilter> registration = new FilterRegistrationBean<>(
				filter);
		registration.setEnabled(false);
		return registration;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		if (!isCSRFEnable) {
			http = http.csrf().disable();
		} else{
			http.csrf().ignoringAntMatchers(csrfIgnoreUrls)
				.csrfTokenRepository(this.getCsrfTokenRepository());
		}

		http.authorizeRequests().antMatchers("*").authenticated().and().exceptionHandling()
				.authenticationEntryPoint(new AuthEntryPoint()).and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.addFilterBefore(authFilter(), UsernamePasswordAuthenticationFilter.class);
		if (isCORSEnable) {
			http.addFilterBefore(new CorsFilter(origins), AuthFilter.class);
		}
		http.headers().cacheControl();
		http.headers().frameOptions().sameOrigin();
	}

	private String getApplicationName() {
		String appNames = environment.getProperty("spring.application.name");
		if (!EmptyCheckUtils.isNullEmpty(appNames)) {
			List<String> appNamesList = Stream.of(appNames.split(",")).collect(Collectors.toList());
			return appNamesList.get(0);
		} else {
			throw new RuntimeException("property spring.application.name is not found");
		}
	}

	private CsrfTokenRepository getCsrfTokenRepository() {
		CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		cookieCsrfTokenRepository.setCookiePath("/");
		return cookieCsrfTokenRepository;
	} 
}

class AuthEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			AuthenticationException e) throws IOException {
		httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UNAUTHORIZED");
	}

}
