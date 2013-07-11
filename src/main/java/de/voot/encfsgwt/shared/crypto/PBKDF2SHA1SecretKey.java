package de.voot.encfsgwt.shared.crypto;

import de.voot.encfsgwt.shared.jre.SecretKey;

public class PBKDF2SHA1SecretKey implements SecretKey {

	private static final long serialVersionUID = -3322686031873211670L;

	private final byte[] encoded;

	public PBKDF2SHA1SecretKey(byte[] encoded) {
		this.encoded = encoded;
	}

	@Override
	public String getAlgorithm() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return encoded;
	}

}
