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
