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
