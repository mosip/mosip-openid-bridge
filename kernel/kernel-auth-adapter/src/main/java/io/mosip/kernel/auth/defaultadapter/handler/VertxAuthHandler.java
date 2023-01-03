package io.mosip.kernel.auth.defaultadapter.handler;

import static io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant.AUTH_HEADER;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.annotation.PostConstruct;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import io.mosip.kernel.auth.defaultadapter.config.Generated;
import io.mosip.kernel.auth.defaultadapter.config.RestTemplateInterceptor;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultadapter.helper.VertxTokenValidationHelper;
import io.mosip.kernel.core.authmanager.authadapter.spi.VertxAuthenticationProvider;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.openid.bridge.model.AuthUserDetails;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

@Lazy
@Component
public class VertxAuthHandler implements VertxAuthenticationProvider {
    
    @Autowired
	private RestTemplateInterceptor restInterceptor;
	
	private RestTemplate restTemplate = null;

	@Autowired
	private VertxTokenValidationHelper validationHelper;
	
	private static final String DEFAULTADMIN_MOSIP_IO = "defaultadmin@mosip.io";

	@Value("${mosip.kernel.auth.adapter.ssl-bypass:true}")
	private boolean sslBypass;
	
	@PostConstruct
	void init() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		HttpClientBuilder httpClientBuilder = HttpClients.custom().disableCookieManagement();
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		if (sslBypass) {
			TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
					.loadTrustMaterial(null, acceptingTrustStrategy).build();
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			httpClientBuilder.setSSLSocketFactory(csf);
		}
		requestFactory.setHttpClient(httpClientBuilder.build());
		List<ClientHttpRequestInterceptor> list = new ArrayList<>();
		list.add(restInterceptor);
		restTemplate = new RestTemplate(requestFactory);
		restTemplate.setInterceptors(list);
	}

	@Generated // coverage exclusion as this is a filter
	@Override
    public void addCorsFilter(HttpServer httpServer, Vertx vertx) {
		Router router = Router.router(vertx);
		
		// Basic security headers by OWASP
		router.route().handler(routingContext -> {
			HttpServerResponse httpServerResponse = routingContext.response();
			httpServerResponse.putHeader("Cache-Control", "no-store, no-cache,max-age=0, must-revalidate")
					.putHeader("Pragma", "no-cache").putHeader("X-Content-Type-Options", "nosniff")
					.putHeader("Strict-Transport-Security", "max-age=" + 15768000 + "; includeSubDomains")
					.putHeader("X-Download-Options", "noopen").putHeader("X-XSS-Protection", "1; mode=block")
					.putHeader("X-FRAME-OPTIONS", "DENY");

			routingContext.next();
		});
		httpServer.requestHandler(router);
	}

	@Generated // coverage exclusion as this is a filter
	@Override
	public void addAuthFilter(Router router, String path, HttpMethod httpMethod,
			String commaSepratedRoles) {
		Objects.requireNonNull(httpMethod, AuthAdapterConstant.HTTP_METHOD_NOT_NULL);
		Route filterRoute = router.route(httpMethod, path);
		filterRoute.handler(routingContext -> {
			tokenValidation(routingContext, commaSepratedRoles);
		});
	}

	@Generated // coverage exclusion as this is a filter
	@Override
	public void addAuthFilter(RoutingContext routingContext, String commaSepratedRoles) {
		tokenValidation(routingContext, commaSepratedRoles);
	}

	private void tokenValidation(RoutingContext routingContext, String commaSepratedRoles) {
		try {
			if (EmptyCheckUtils.isNullEmpty(commaSepratedRoles)) {
				throw new NullPointerException(AuthAdapterConstant.ROLES_NOT_EMPTY_NULL);
			}
			String[] roles = commaSepratedRoles.split(",");
			String token = validateToken(routingContext, roles);
			if (!token.isEmpty()) {
				HttpServerResponse httpServerResponse = routingContext.response();
				if (!token.startsWith(AUTH_HEADER))
					token = AUTH_HEADER + token;
				httpServerResponse.putHeader(AuthAdapterConstant.AUTH_HEADER_SET_COOKIE, token);
				routingContext.next();
			}
		} catch (Exception e) {
			throw new AuthManagerException(String.valueOf(HttpStatus.UNAUTHORIZED.value()), e.getMessage(), e);
		}
	}

	private String validateToken(RoutingContext routingContext, String[] roles)
			throws RestClientException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException,
			JsonParseException, JsonMappingException, JsonProcessingException, IOException {
		
		MosipUserDto mosipUserDto = validationHelper.getTokenValidatedVertxUserResponse(restTemplate, routingContext, roles);
		if (Objects.isNull(mosipUserDto)) {
			return "";
		}

		AuthUserDetails authUserDetails = new AuthUserDetails(mosipUserDto, mosipUserDto.getToken());
		Authentication authentication = new UsernamePasswordAuthenticationToken(authUserDetails,
				authUserDetails.getPassword(), null);
		routingContext.put(AuthAdapterConstant.ROUTING_CONTEXT_USER, mosipUserDto);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		return mosipUserDto.getToken();
	}

	@Override
	public String getContextUser(RoutingContext routingContext) {
		MosipUserDto mosipUser = routingContext.get(AuthAdapterConstant.ROUTING_CONTEXT_USER);
		return mosipUser == null ? DEFAULTADMIN_MOSIP_IO : mosipUser.getUserId();
	}
}
