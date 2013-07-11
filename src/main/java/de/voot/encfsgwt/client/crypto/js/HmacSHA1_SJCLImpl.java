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
