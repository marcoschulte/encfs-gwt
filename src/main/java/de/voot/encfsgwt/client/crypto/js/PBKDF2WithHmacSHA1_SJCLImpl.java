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
package de.voot.encfsgwt.client.crypto.js;

public class PBKDF2WithHmacSHA1_SJCLImpl {
	public native static String generateSecret(String password, int iter, String b64Salt, int keyLength) /*-{
		var sjcl = $wnd.sjcl;

		var hmac = function(key) {
			return new sjcl.misc.hmac(key, sjcl.hash.sha1);
		};

		salt = sjcl.codec.base64.toBits(b64Salt);
		var key = sjcl.misc.pbkdf2(password, salt, iter, keyLength, hmac);
		key = sjcl.codec.base64.fromBits(key);
		return key;
	}-*/;
}
