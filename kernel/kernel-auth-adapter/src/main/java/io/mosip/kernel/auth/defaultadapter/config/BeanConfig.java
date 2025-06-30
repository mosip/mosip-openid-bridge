package io.mosip.kernel.auth.defaultadapter.config;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.core5.util.Timeout;
import org.apache.http.conn.ssl.TrustStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.loadbalancer.reactive.ReactorLoadBalancerExchangeFilterFunction;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.TokenHolder;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.openid.bridge.model.AuthUserDetails;

@Configuration
@EnableScheduling
public class BeanConfig {

	@Autowired
	private TokenHelper tokenHelper;

	@Autowired
	private Environment environment;

	@Autowired 
	private RestTemplateInterceptor defaultInterceptor;

	@Value("${mosip.kernel.auth.adapter.ssl-bypass:true}")
	private boolean sslBypass;

	@Value("${mosip.kernel.http.default.restTemplate.max-connection-per-route:20}")
	private Integer defaultRestTemplateMaxConnectionPerRoute;

	@Value("${mosip.kernel.http.default.restTemplate.total-max-connections:100}")
	private Integer defaultRestTemplateTotalMaxConnections;

	@Value("${mosip.kernel.http.selftoken.restTemplate.max-connection-per-route:20}")
	private Integer selfTokenRestTemplateMaxConnectionPerRoute;

	@Value("${mosip.kernel.http.selftoken.restTemplate.total-max-connections:100}")
	private Integer selfTokenRestTemplateTotalMaxConnections;

	@Value("${mosip.kernel.http.plain.restTemplate.max-connection-per-route:20}")
	private Integer plainRestTemplateMaxConnectionPerRoute;

	@Value("${mosip.kernel.http.plain.restTemplate.total-max-connections:100}")
	private Integer plainRestTemplateTotalMaxConnections;

	@Value("${mosip.kernel.webclient.exchange.strategy.max-in-memory-size.mbs:0}")
	private Integer exchangeStrategyMaxMemory;

	@Value("${mosip.kernel.http.selftoken.restTemplate.socket-timeout:0}")
	private Integer selfTokenRestTemplateSocketTimeout;

	@Autowired
	private TokenValidationHelper tokenValidationHelper;

	private static final Logger LOGGER = LoggerFactory.getLogger(BeanConfig.class);
	
	@Autowired(required = false)
	private ReactorLoadBalancerExchangeFilterFunction lbFilterFunction;

	@SuppressWarnings("java:S5527") // added suppress for sonarcloud. 
	// Server hostname verification is not required because of 2 reasons:
	// 1. All services will not be enabled to reach to out side network to get data.
	// 2. All internal service will have custom host names Eg: identity.idrepo
	// sslBypass will be set to true by default because it will be ignore only for the restTemplate object 
	// which will be used to reach to other servcies.  
	@Bean
	public RestTemplate restTemplate() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		var connnectionManagerBuilder = PoolingHttpClientConnectionManagerBuilder.create()
			     .setMaxConnPerRoute(defaultRestTemplateMaxConnectionPerRoute)
			     .setMaxConnTotal(defaultRestTemplateTotalMaxConnections);

		RestTemplate restTemplate = null;
		if (sslBypass) {
			TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
					.loadTrustMaterial(acceptingTrustStrategy).build();
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			connnectionManagerBuilder.setSSLSocketFactory(csf);
		}
		var connectionManager = connnectionManagerBuilder.build();
		HttpClientBuilder httpClientBuilder = HttpClients.custom()
				.setConnectionManager(connectionManager)
				.disableCookieManagement();
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
		restTemplate = new RestTemplate(requestFactory);
		restTemplate.setInterceptors(Collections.singletonList(new RequesterTokenRestInterceptor()));
		// interceptor added in RestTemplatePostProcessor
		return restTemplate;
	}

	// this is just used by client token interceptor to call to renew and validate
	// token
	@Bean
	public RestTemplate plainRestTemplate() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException{
		
		var connnectionManagerBuilder = PoolingHttpClientConnectionManagerBuilder.create()
			     .setMaxConnPerRoute(plainRestTemplateMaxConnectionPerRoute)
			     .setMaxConnTotal(plainRestTemplateTotalMaxConnections);
		var connectionManager = connnectionManagerBuilder.build();
		
		HttpClientBuilder httpClientBuilder = HttpClients.custom()
				.setConnectionManager(connectionManager)
				.disableCookieManagement();
		
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
		RestTemplate template = new RestTemplate(requestFactory);
		template.setInterceptors(Collections.singletonList(defaultInterceptor));
		return template;
	}

	@Bean
	public TokenHolder<String> cachedTokenObject() {
		return new TokenHolder<>();
	}

	@SuppressWarnings("java:S5527") // added suppress for sonarcloud.
	// Refer comments above.
	@Bean
	public RestTemplate selfTokenRestTemplate(@Autowired @Qualifier("plainRestTemplate") RestTemplate plainRestTemplate,
			@Autowired TokenHolder<String> cachedTokenObject)
			throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		var connnectionManagerBuilder = PoolingHttpClientConnectionManagerBuilder.create()
			     .setMaxConnPerRoute(selfTokenRestTemplateMaxConnectionPerRoute)
			     .setMaxConnTotal(selfTokenRestTemplateTotalMaxConnections);
		
		RestTemplate restTemplate = null;
		if (sslBypass) {
			TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
					.loadTrustMaterial(acceptingTrustStrategy).build();
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			connnectionManagerBuilder.setSSLSocketFactory(csf);
		}
		var connectionManager = connnectionManagerBuilder.build();
		HttpClientBuilder httpClientBuilder = HttpClients.custom()
				.setConnectionManager(connectionManager)
				.disableCookieManagement();

		//Setting the timeout in case reading data from socket takes more timeAdd commentMore actions
		if(selfTokenRestTemplateSocketTimeout != 0){
			LOGGER.info("Setting selfTokenRestTemplateSocketTimeout :"+ selfTokenRestTemplateSocketTimeout);
			RequestConfig config = RequestConfig.custom().setResponseTimeout(Timeout.ofMilliseconds(selfTokenRestTemplateSocketTimeout)).build();
			httpClientBuilder.setDefaultRequestConfig(config);
		}
		String applName = getApplicationName();
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
		restTemplate = new RestTemplate(requestFactory);
		restTemplate.setInterceptors(Collections.singletonList(new SelfTokenRestInterceptor(environment,
				plainRestTemplate, cachedTokenObject, tokenHelper, tokenValidationHelper, applName)));
		// interceptor added in RestTemplatePostProcessor
		return restTemplate;
	}

	@Bean
	public WebClient plainWebClient() {
		ExchangeFilterFunction filterFunction = (lbFilterFunction != null)
				? lbFilterFunction
				: (req, next) -> {
					return next.exchange(req);
				};
		return WebClient.builder().filter(filterFunction).build();
	}

	@Bean
	public SelfTokenRenewalTaskExecutor selfTokenRenewTaskExecutor(@Autowired TokenHolder<String> cachedTokenObject,
			@Autowired @Qualifier("plainWebClient") WebClient plainWebClient)
			throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		String applName = getApplicationName();
		return new SelfTokenRenewalTaskExecutor(cachedTokenObject, plainWebClient, tokenHelper, environment, applName);
	}

	@Bean
	public WebClient webClient() {

		return WebClient.builder().filter((req, next) -> {
			ClientRequest filtered = null;
			if (SecurityContextHolder.getContext() != null
					&& SecurityContextHolder.getContext().getAuthentication().getPrincipal() != null
					&& SecurityContextHolder.getContext().getAuthentication()
							.getPrincipal() instanceof AuthUserDetails) {
				io.mosip.kernel.openid.bridge.model.AuthUserDetails userDetail = (AuthUserDetails) SecurityContextHolder.getContext().getAuthentication()
						.getPrincipal();
				filtered = ClientRequest.from(req).header(AuthAdapterConstant.AUTH_HEADER_COOKIE,
						AuthAdapterConstant.AUTH_HEADER + userDetail.getToken()).build();
			}
			return next.exchange(filtered);
		}).build();
	}

	@Bean
	public WebClient selfTokenWebClient(@Autowired @Qualifier("plainWebClient") WebClient plainWebClient,
			@Autowired TokenHolder<String> cachedTokenObject) {
		String applName = getApplicationName();
		
		if (exchangeStrategyMaxMemory <= 0)
			return WebClient.builder()
							.filter(new SelfTokenExchangeFilterFunction(environment, plainWebClient,
									cachedTokenObject, tokenHelper, tokenValidationHelper, applName))
							.build();
		// Added ExchangeStrategies to increase the buffer size for requests between service.
		// Found size limitation issue in ID Repo service which is invoking encrypt API of keymanager service.
		int size = exchangeStrategyMaxMemory * 1024 * 1024;
		ExchangeStrategies strategies = ExchangeStrategies.builder()
										.codecs(codecs -> codecs.defaultCodecs().maxInMemorySize(size))
										.build();
		return WebClient.builder()
						.filter(new SelfTokenExchangeFilterFunction(environment, plainWebClient,
								cachedTokenObject, tokenHelper, tokenValidationHelper, applName))
						.exchangeStrategies(strategies)
						.build();
	}

	@SuppressWarnings("java:S2259") // added suppress for sonarcloud. Null check is performed at line # 211
	private String getApplicationName() {
		String appNames = environment.getProperty("spring.application.name");
		if (appNames != null && !EmptyCheckUtils.isNullEmpty(appNames)) {
			List<String> appNamesList = Stream.of(appNames.split(",")).collect(Collectors.toList());
			return appNamesList.get(0);
		} else {
			throw new RuntimeException("Property spring.application.name not found");
		}
	}
}
