package io.mosip.kernel.auth.defaultadapter.helper;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.List;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import io.mosip.kernel.openid.bridge.model.AuthUserDetails;

@RunWith(MockitoJUnitRunner.class)
public class ScopeValidatorImplTest {
	
	@Mock
	private Authentication authentication;
	
	@Mock
	private AuthUserDetails principal;

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Before
	public void setUp() throws Exception {
		when(authentication.getPrincipal()).thenReturn(principal);
		when(principal.getAuthorities()).thenReturn((Collection) List.of(new SimpleGrantedAuthority("SCOPE_aaa"),  new SimpleGrantedAuthority("SCOPE_bbb")));
		SecurityContextHolder.getContext().setAuthentication(authentication);

	}

	private ScopeValidatorImpl createTestSubject() {
		return new ScopeValidatorImpl();
	}
	
	@Test
	public void testHasAllScopes_nullScopes() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = null;
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasAllScopes(scopes);
		assertFalse(result);
	}
	
	@Test
	public void testHasAllScopes_emptyScopes() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = null;
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasAllScopes(scopes);
		assertFalse(result);
	}

	@Test
	public void testHasAllScopes() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = List.of("aaa", "bbb");
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasAllScopes(scopes);
		assertTrue(result);
	}
	
	@Test
	public void testHasAllScopes_negative_allmissing() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = List.of("ccc", "ddd");
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasAllScopes(scopes);
		assertFalse(result);
	}
	
	@Test
	public void testHasAllScopes_negative_somemissing() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = List.of("bbb", "ccc");
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasAllScopes(scopes);
		assertFalse(result);
	}

	@Test
	public void testHasAnyScopes() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = List.of("aaa", "bbb");
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasAnyScopes(scopes);
		assertTrue(result);
	}
	
	@Test
	public void testHasAnyScopes_positive_somepresent() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = List.of("bbb", "ccc");
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasAnyScopes(scopes);
		assertTrue(result);
	}
	
	@Test
	public void testHasAnyScopes_negative_nonepresent() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = List.of("ccc", "ddd");
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasAnyScopes(scopes);
		assertFalse(result);
	}

	@Test
	public void testHasScope() throws Exception {
		ScopeValidatorImpl testSubject;
		String scope = "aaa";
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasScope(scope);
		assertTrue(result);
	}
	
	@Test
	public void testHasScope_negative() throws Exception {
		ScopeValidatorImpl testSubject;
		String scope = "ccc";
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasScope(scope);
		assertFalse(result);
	}

	@Test
	public void testHasScopes() throws Exception {
		ScopeValidatorImpl testSubject;
		List<String> scopes = List.of("aaa", "bbb");
		BiPredicate<Stream<String>, Predicate<? super String>> condition = Stream::anyMatch;
		boolean result;

		// default test
		testSubject = createTestSubject();
		result = testSubject.hasScopes(scopes, condition);
		assertTrue(result);
	}
}