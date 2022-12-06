package io.mosip.kernel.authcodeflowproxy.api.service.validator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TestJWT {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, IOException {
		// PEM-encoded private RSA key generated with
		// openssl genpkey -algorithm RSA -out priv.pem -pkeyopt rsa_keygen_bits:2048

		String certPEM = new String(Files.readAllBytes(new File(args[0]).toPath()));

		// Parse PEM-encoded key to RSA public / private JWK
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) f
				.generateCertificate(new ByteArrayInputStream(certPEM.getBytes()));
		RSAPublicKey pk = (RSAPublicKey) certificate.getPublicKey();
		System.out.println(new ObjectMapper().writeValueAsString(generateJWK(pk)));

	}

	private static Map<String, Object> generateJWK(PublicKey publicKey) {

		RSAPublicKey rsa = (RSAPublicKey) publicKey;

		Map<String, Object> values = new HashMap<>();

		values.put("kty", rsa.getAlgorithm()); // getAlgorithm() returns kty not algorithm
		values.put("kid", UUID.randomUUID().toString());
		values.put("n", java.util.Base64.getUrlEncoder().encodeToString(rsa.getModulus().toByteArray()));
		values.put("e", java.util.Base64.getUrlEncoder().encodeToString(rsa.getPublicExponent().toByteArray()));
		values.put("alg", "RS256");
		values.put("use", "sig");

		return values;
	}

}
