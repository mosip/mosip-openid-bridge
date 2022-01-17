package io.mosip.kernel.auth.repo.test;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.auth.defaultimpl.repository.impl.LdapDataStore;
import io.mosip.kernel.auth.test.AuthTestBootApplication;
import io.mosip.kernel.core.authmanager.model.UserRegistrationRequestDto;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class LdapDataStoreTest { 
	
	@Autowired
	private LdapDataStore ldapDataStore;

	@Test
	public void registerUserTest() throws Exception  {
		UserRegistrationRequestDto userCreationRequestDto = new UserRegistrationRequestDto();
		userCreationRequestDto.setAppId("ida");
		userCreationRequestDto.setUserName("110005");
		userCreationRequestDto.setUserPassword("abc");
		userCreationRequestDto.setRole("PROCESSOR");
		userCreationRequestDto.setGender("MALE");
		ldapDataStore.registerUser(userCreationRequestDto);
	}
	
	
	
}
