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

import de.voot.encfsgwt.client.crypto.js.HmacSHA1_SJCLImpl;
import de.voot.encfsgwt.shared.jre.Base64;
import de.voot.encfsgwt.shared.jre.NoSuchAlgorithmException;
import de.voot.encfsgwt.shared.jre.SecretKeySpec;
import de.voot.encfsgwt.shared.util.ArrayUtil;

public abstract class Mac implements Cloneable {

	public static final String HMAC_SHA1 = "HmacSHA1";

	public abstract byte[] doFinal();

	public abstract byte[] doFinal(byte[] data);

	public abstract void init(SecretKeySpec key);

	public abstract void reset();

	public abstract void update(byte[] input, int offset, int len);

	public static Mac getInstance(String string) throws NoSuchAlgorithmException {
		if (HMAC_SHA1.equals(string)) {
			return new HmacSHA1Wrapper();
		}

		throw new NoSuchAlgorithmException();
	}

	private static class HmacSHA1Wrapper extends Mac {

		private SecretKeySpec key;
		private StringBuilder builder;

		@Override
		public byte[] doFinal() {
			String str = HmacSHA1_SJCLImpl.encrypt(Base64.byteArrayToBase64(key.getEncoded()), builder.toString());
			reset();
			return Base64.base64ToByteArray(str);
		}

		@Override
		public byte[] doFinal(byte[] data) {
			update(data, 0, data.length);
			return doFinal();
		}

		@Override
		public void init(SecretKeySpec key) {
			this.key = key;
			reset();
		}

		@Override
		public void reset() {
			builder = new StringBuilder();
		}

		@Override
		public void update(byte[] data, int offset, int len) {
			byte[] bytes = ArrayUtil.copyOfRange(data, offset, offset + len);
			builder.append(Base64.byteArrayToBase64(bytes));
		}

	}
}
