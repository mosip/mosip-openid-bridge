package io.mosip.kernel.openid.bridge.model;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * MOSIP USER IS THE STANDARD SPEC THAT WILL BE TUNED BASED ON THE DETAILS
 * STORED IN LDAP FOR A USER
 *
 * @author Sabbu Uday Kumar
 * @since 1.0.0
 */

@Data
@EqualsAndHashCode(callSuper=true)
public class MosipUserDto extends io.mosip.kernel.core.authmanager.authadapter.model.MosipUserDto {
}