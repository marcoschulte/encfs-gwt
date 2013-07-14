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

public class AES_CBC_NoPadding_SJCLImpl {

	public native static String decrypt(String b64Key, String b64Cipher, String b64IV) /*-{
		var sjcl = $wnd.sjcl;

		var key = sjcl.codec.base64.toBits(b64Key);
		var cipher = sjcl.codec.base64.toBits(b64Cipher);
		var iv = sjcl.codec.base64.toBits(b64IV);

		var aes = new sjcl.cipher.aes(key);
		var plain = sjcl.mode.cbc.decrypt(aes, cipher, iv);
		return sjcl.codec.base64.fromBits(plain);
	}-*/;

	public native static String encrypt(String b64Key, String b64Plain, String b64IV) /*-{
		var sjcl = $wnd.sjcl;

		var key = sjcl.codec.base64.toBits(b64Key);
		var plain = sjcl.codec.base64.toBits(b64Plain);
		var iv = sjcl.codec.base64.toBits(b64IV);

		var aes = new sjcl.cipher.aes(key);
		var cipher = sjcl.mode.cbc.encrypt(aes, plain, iv);
		return sjcl.codec.base64.fromBits(cipher);
	}-*/;
}
