
package io.mosip.kernel.auth.defaultadapter.handler;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.auth0.jwt.JWT;
import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import io.mosip.kernel.auth.defaultadapter.config.RestTemplateInterceptor;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.AuthToken;
import io.mosip.kernel.openid.bridge.model.AuthUserDetails;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;

/**
 * Contacts auth server to verify token validity.
 *
 * Tasks: 1. Contacts auth server to verify token validity. 2. Stores the
 * response body in an instance of MosipUserDto. 3. Updates token into in the
 * security context through AuthUserDetails. 4. Bind MosipUserDto instance
 * details with the AuthUserDetails that extends Spring Security's UserDetails.
 * 
 * @author Ramadurai Saravana Pandian
 * @author Raj Jha
 * @author Urvil Joshi
 * @since 1.0.0
 */
@Component
public class AuthHandler extends AbstractUserDetailsAuthenticationProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthHandler.class);

	@Autowired
	private RestTemplateInterceptor restInterceptor;
	
	private RestTemplate restTemplate = null;

	@Autowired
	private TokenValidationHelper validationHelper;
	
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

	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
	}

	@Override
	protected UserDetails retrieveUser(String userName,
			UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
		AuthToken authToken = (AuthToken) usernamePasswordAuthenticationToken;
		String token = authToken.getToken();
		String idToken = authToken.getIdToken();
		MosipUserDto mosipUserDto = validationHelper.getTokenValidatedUserResponse(token, restTemplate);
		
		List<GrantedAuthority> roleAuthorities = AuthorityUtils
				.commaSeparatedStringToAuthorityList(mosipUserDto.getRole());
		
		AuthUserDetails authUserDetails;
		if(idToken!=null){
			authUserDetails = new AuthUserDetails(mosipUserDto, token, idToken);
		} else{
			authUserDetails = new AuthUserDetails(mosipUserDto, token);
		}
		authUserDetails.addRoleAuthorities(roleAuthorities);
		
		Optional<String> scopeClaimOpt = getScopeClaim(token);
		if(scopeClaimOpt.isPresent()) {
			List<GrantedAuthority> scopeAuthorities = AuthorityUtils
					.createAuthorityList(StringUtils
							.tokenizeToStringArray(scopeClaimOpt.get() , " "));
			authUserDetails.addScopeAuthorities(scopeAuthorities);
		}
		return authUserDetails;

	}

	private Optional<String> getScopeClaim(String jwtToken) {
		 DecodedJWT decodedJWT = JWT.decode(jwtToken);
		Claim claim = decodedJWT.getClaim(AuthAdapterConstant.SCOPE);
		if(claim != null && !(claim instanceof NullClaim)) {
			String scopesStr = claim.asString();
			return Optional.of(scopesStr);
		}
		return Optional.empty();
	}
}
