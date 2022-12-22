/**
 * 
 */
package io.mosip.kernel.openid.bridge.api.service;

import io.mosip.kernel.core.authmanager.model.MosipUserTokenDto;

/**
 * @author Ramadurai Pandian
 *
 */
public interface AuthZService {

	MosipUserTokenDto validateToken(String token) throws Exception;

}
