package io.mosip.kernel.auth.defaultadapter.model;

import java.util.List;

import lombok.Data;

/**
 * @author GOVINDARAJ VELU
 * It is used to store the service end-points to access without authentication
 */
@Data
public class ServiceEndPoint {
	List<String> endPoints;
}
