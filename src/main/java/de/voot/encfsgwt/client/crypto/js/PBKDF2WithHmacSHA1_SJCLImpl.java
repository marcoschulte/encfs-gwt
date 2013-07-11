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
