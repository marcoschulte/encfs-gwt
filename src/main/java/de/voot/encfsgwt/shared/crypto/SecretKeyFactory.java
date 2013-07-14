/*
  	Copyright (C) 2013 Marco Schulte

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
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
