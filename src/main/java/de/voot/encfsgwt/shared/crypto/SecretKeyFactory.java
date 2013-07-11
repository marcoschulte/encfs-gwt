package de.voot.encfsgwt.shared.crypto;

import de.voot.encfsgwt.client.crypto.js.PBKDF2WithHmacSHA1_SJCLImpl;
import de.voot.encfsgwt.shared.jre.Base64;
import de.voot.encfsgwt.shared.jre.InvalidKeySpecException;
import de.voot.encfsgwt.shared.jre.KeySpec;
import de.voot.encfsgwt.shared.jre.NoSuchAlgorithmException;
import de.voot.encfsgwt.shared.jre.PBEKeySpec;
import de.voot.encfsgwt.shared.jre.SecretKey;

public abstract class SecretKeyFactory {

	public static final String PBKDF2_WITH_HMAC_SHA1 = "PBKDF2WithHmacSHA1";

	public abstract SecretKey generateSecret(KeySpec ks) throws InvalidKeySpecException;

	public static SecretKeyFactory getInstance(String string) throws NoSuchAlgorithmException {
		if (PBKDF2_WITH_HMAC_SHA1.equals(string)) {
			return new PBKDF2KeyFactory();
		}

		throw new NoSuchAlgorithmException();
	}

	private static class PBKDF2KeyFactory extends SecretKeyFactory {

		@Override
		public SecretKey generateSecret(KeySpec ks) throws InvalidKeySpecException {
			PBEKeySpec pbeKeySpec = (PBEKeySpec) ks;

			String key = PBKDF2WithHmacSHA1_SJCLImpl.generateSecret(new String(pbeKeySpec.getPassword()), pbeKeySpec.getIterationCount(),
					Base64.byteArrayToBase64(pbeKeySpec.getSalt()), pbeKeySpec.getKeyLength());

			byte[] bytes = Base64.base64ToByteArray(key);

			return new PBKDF2SHA1SecretKey(bytes);
		};

	}
}
