package io.mosip.kernel.openid.bridge.dto;

import lombok.Data;

@Data
public class IAMErrorResponseDto {

	/** The error. */
	private String error;

	/** The error description. */
	private String error_description;
}