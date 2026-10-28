package io.mosip.kernel.openid.bridge.api.utils;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Verification only {@link Algorithm} for PS256, which java-jwt 3.8.1 does not
 * provide. Throws {@link SignatureVerificationException} like the RSA
 * algorithms, so callers handle it in the same way.
 */
public class PssAlgorithm extends Algorithm {

	private final PublicKey publicKey;

	private PssAlgorithm(PublicKey publicKey) {
		super("PS256", "RSASSA-PSS using SHA-256 and MGF1");
		this.publicKey = publicKey;
	}

	public static Algorithm PS256(PublicKey publicKey) {
		return new PssAlgorithm(publicKey);
	}

	@Override
	public void verify(DecodedJWT jwt) throws SignatureVerificationException {
		try {
			Signature signature = Signature.getInstance("RSASSA-PSS");
			signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
			signature.initVerify(publicKey);
			signature.update((jwt.getHeader() + "." + jwt.getPayload()).getBytes(US_ASCII));
			if (!signature.verify(Base64.getUrlDecoder().decode(jwt.getSignature()))) {
				throw new SignatureVerificationException(this);
			}
		} catch (GeneralSecurityException | IllegalArgumentException e) {
			throw new SignatureVerificationException(this, e);
		}
	}

	@Override
	public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
		throw new SignatureGenerationException(this,
				new UnsupportedOperationException("PssAlgorithm can only verify signatures"));
	}
}
