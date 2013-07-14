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

import de.voot.encfsgwt.client.crypto.js.AES_CBC_NoPadding_SJCLImpl;
import de.voot.encfsgwt.client.crypto.js.AES_CFB_NoPadding_SJCLImpl;
import de.voot.encfsgwt.shared.jre.Base64;
import de.voot.encfsgwt.shared.jre.InvalidKeyException;
import de.voot.encfsgwt.shared.jre.IvParameterSpec;
import de.voot.encfsgwt.shared.jre.Key;
import de.voot.encfsgwt.shared.jre.NoSuchAlgorithmException;
import de.voot.encfsgwt.shared.jre.NoSuchPaddingException;
import de.voot.encfsgwt.shared.util.ArrayUtil;

public abstract class Cipher {

	public static final String AES_CBC_NO_PADDING = "AES/CBC/NoPadding";
	public static final String AES_CFB_NO_PADDING = "AES/CFB/NoPadding";
	public static final int ENCRYPT_MODE = 1;
	public static final int DECRYPT_MODE = 2;

	public abstract byte[] doFinal(byte[] data);

	public abstract byte[] doFinal(byte[] data, int offset, int len);

	public abstract void init(int opMode, Key key, IvParameterSpec ivSpec) throws InvalidKeyException;

	public static Cipher getInstance(String cipherSpec) throws NoSuchAlgorithmException, NoSuchPaddingException {
		if (AES_CFB_NO_PADDING.equals(cipherSpec)) {
			return new AES_SJCL_Wrapper(AES_SJCL_Wrapper.MODE_CFB);
		} else if (AES_CBC_NO_PADDING.equals(cipherSpec)) {
			return new AES_SJCL_Wrapper(AES_SJCL_Wrapper.MODE_CBC);
		}

		throw new NoSuchAlgorithmException();
	}

	private static class AES_SJCL_Wrapper extends Cipher {

		public static final String MODE_CBC = "CBC";
		public static final String MODE_CFB = "CFB";

		private int opMode;
		private Key key;
		private IvParameterSpec ivParameterSpec;
		private final String mode;

		public AES_SJCL_Wrapper(String mode) {
			this.mode = mode;
		}

		@Override
		public byte[] doFinal(byte[] data) {
			int len = data.length;
			if ((data.length & 15) != 0) {
				// length of block != multiple of 128 bits, we need to pad to
				// the next full 128bit = 16 byte
				int mask = Integer.MAX_VALUE ^ 0x0F;
				int newSize = (data.length & mask) + 16;
				byte[] padded = new byte[newSize];
				System.arraycopy(data, 0, padded, 0, data.length);
				data = padded;
			}

			byte[] result = null;

			if (opMode == DECRYPT_MODE) {
				if (MODE_CBC.equals(mode)) {
					String ct = AES_CBC_NoPadding_SJCLImpl.decrypt(Base64.byteArrayToBase64(key.getEncoded()), Base64.byteArrayToBase64(data),
							Base64.byteArrayToBase64(ivParameterSpec.getIV()));
					result = Base64.base64ToByteArray(ct);
				} else if (MODE_CFB.equals(mode)) {
					String ct = AES_CFB_NoPadding_SJCLImpl.decrypt(Base64.byteArrayToBase64(key.getEncoded()), Base64.byteArrayToBase64(data),
							Base64.byteArrayToBase64(ivParameterSpec.getIV()));
					result = Base64.base64ToByteArray(ct);
				}
			} else if (opMode == ENCRYPT_MODE) {
				if (MODE_CBC.equals(mode)) {
					String ct = AES_CBC_NoPadding_SJCLImpl.encrypt(Base64.byteArrayToBase64(key.getEncoded()), Base64.byteArrayToBase64(data),
							Base64.byteArrayToBase64(ivParameterSpec.getIV()));
					result = Base64.base64ToByteArray(ct);
				} else if (MODE_CFB.equals(mode)) {
					String ct = AES_CFB_NoPadding_SJCLImpl.encrypt(Base64.byteArrayToBase64(key.getEncoded()), Base64.byteArrayToBase64(data),
							Base64.byteArrayToBase64(ivParameterSpec.getIV()));
					result = Base64.base64ToByteArray(ct);
				}
			}

			if (len != result.length) {
				// remove padding
				byte[] newResult = new byte[len];
				System.arraycopy(result, 0, newResult, 0, len);
				result = newResult;
			}
			return result;
		}

		@Override
		public byte[] doFinal(byte[] data, int offset, int len) {
			if (offset != 0 || len != data.length)
				data = ArrayUtil.copyOfRange(data, offset, offset + len);

			return doFinal(data);
		}

		@Override
		public void init(int opMode, Key key, IvParameterSpec ivSpec) throws InvalidKeyException {
			if (key.getEncoded().length != 16 && key.getEncoded().length != 24 && key.getEncoded().length != 32) {
				throw new InvalidKeyException("Keysize must be 128, 192 or 256bits");
			}
			if (opMode != ENCRYPT_MODE && opMode != DECRYPT_MODE) {
				throw new UnsupportedOperationException("Mode not supported.");
			}

			this.opMode = opMode;
			this.key = key;
			this.ivParameterSpec = ivSpec;
		}
	}
}