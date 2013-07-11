package de.voot.encfsgwt.shared.util;

import java.io.IOException;

import de.voot.encfsgwt.shared.jre.InputStream;

public class StreamUtil {

	public static String readToString(InputStream inputStream) throws IOException {
		StringBuilder builder = new StringBuilder();

		int bufSize = 1024;
		byte[] buf = new byte[bufSize];
		int length;
		while ((length = inputStream.read(buf)) > -1) {
			String s = null;
			if (length < bufSize) {
				s = new String(ArrayUtil.copyOf(buf, length));
			} else {
				s = new String(buf);
			}
			builder.append(s);
		}

		return builder.toString();
	}

	public static byte[] readToBytes(InputStream inputStream) throws IOException {
		String s = readToString(inputStream);
		return s.getBytes();
	}

}
