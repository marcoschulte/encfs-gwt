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

public class HmacSHA1_SJCLImpl {

	public native static String encrypt(String b64Key, String b64Data) /*-{
		var sjcl = $wnd.sjcl;

		var key = sjcl.codec.base64.toBits(b64Key);
		var data = sjcl.codec.base64.toBits(b64Data);

		var hmac = new sjcl.misc.hmac(key, sjcl.hash.sha1);
		var bits = hmac.encrypt(data);

		var b64 = sjcl.codec.base64.fromBits(bits);
		return b64;
	}-*/;
}
