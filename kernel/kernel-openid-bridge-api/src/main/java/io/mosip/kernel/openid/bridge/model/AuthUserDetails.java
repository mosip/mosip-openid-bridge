package io.mosip.kernel.openid.bridge.model;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/***********************************************************************************************************************
 * Used by spring security to store user details like roles and use this across
 * the application for Authorization purpose. The user details can be fetched
 * using principal in SecurityContextHolder
 *
 * @author Sabbu Uday Kumar
 * @since 1.0.0
 **********************************************************************************************************************/

public class AuthUserDetails extends io.mosip.kernel.core.authmanager.authadapter.model.AuthUserDetails {

	/**
	 * 
	 */
	private static final long serialVersionUID = 867530372652743714L;

	public static final String SCOPE_AUTHORITY_PREFIX = "SCOPE_";

	public static final String ROLE_AUTHORITY_PREFIX = "ROLE_";

	/**
	 * 
	 */
	private String idToken;

	private Collection<? extends GrantedAuthority> authorities;

	public AuthUserDetails(MosipUserDto mosipUserDto, String token) {
		super(mosipUserDto, token);
	}

	public AuthUserDetails(MosipUserDto mosipUserDto, String token, String idToken) {
		this(mosipUserDto, token);
		this.idToken = idToken;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	private void addAuthorities(Collection<? extends GrantedAuthority> authorities, String authorityPrefix) {
		Stream<SimpleGrantedAuthority> authortiesStream = authorities.stream().map(grantedAuthority -> {
			String authority = authorityPrefix == null ?  grantedAuthority.getAuthority() : authorityPrefix + grantedAuthority.getAuthority();
			return new SimpleGrantedAuthority(authority);
		});
		
		if(this.authorities == null) {
			this.authorities = Collections.unmodifiableCollection(authortiesStream
					.collect(Collectors.toList()));
		} else {
			this.authorities = Collections.unmodifiableCollection(Stream.concat(this.authorities.stream(), authortiesStream)
					.collect(Collectors.toList()));
		}
	}
	
	public void addRoleAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.addAuthorities(authorities, ROLE_AUTHORITY_PREFIX);
	}
	
	public void addScopeAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.addAuthorities(authorities, SCOPE_AUTHORITY_PREFIX);
	}
	
	@Deprecated
	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.addRoleAuthorities(authorities);
	}

	public String getIdToken() {
		return idToken;
	}

	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}
}