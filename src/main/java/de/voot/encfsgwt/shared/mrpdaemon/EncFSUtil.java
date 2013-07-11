/*
 * EncFS Java Library
 * Copyright (C) 2011 Mark R. Pariente
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

package de.voot.encfsgwt.shared.mrpdaemon;

import java.io.IOException;

import de.voot.encfsgwt.shared.jre.InputStream;
import de.voot.encfsgwt.shared.jre.OutputStream;

/**
 * Class containing static methods implementing misc. functionality for the rest
 * of the library
 */
public final class EncFSUtil {

	private static final int EIGHT = 8;
	private static final int EIGHT_KILO = 8192;

	EncFSUtil() {
	}

	/**
	 * Convert the given byte array to 'int'
	 * 
	 * @param b
	 *            A 4-byte array
	 * 
	 * @return int value of the array contents
	 */
	public static int convertBigEndianByteArrayToInt(byte[] b) {
		int capacity = Integer.SIZE / EIGHT;
		if (b.length > capacity) {
			return -1;
		}

		int result = 0;
		for (int i = 0; i < b.length; i++) {
			int shift = (b.length - 1 - i) * 8;
			result |= (b[i] & 0x000000FF) << shift;
		}
		return result;
	}

	/**
	 * Convert the given int to a 4-byte array
	 * 
	 * @param i
	 *            An 'int'
	 * 
	 * @return A 4-byte array in big endian (MSB) ordering
	 */
	public static byte[] convertIntToByteArrayBigEndian(int i) {
		byte[] result = new byte[Integer.SIZE / 8];
		for (int j = 0; j < result.length; j++) {
			int shift = (result.length - 1 - j) * 8;
			result[j] = (byte) ((i >> shift) & 0xFF);
		}
		return result;
	}

	/**
	 * Convert the given byte array to 'long'
	 * 
	 * @param b
	 *            An 8-byte array
	 * @return long value of the array contents
	 */
	public static long convertByteArrayToLong(byte[] b) {
		int capacity = Long.SIZE / EIGHT;
		if (b.length > capacity) {
			return -1;
		}

		long result = 0;
		for (int i = 0; i < b.length; i++) {
			int shift = (b.length - 1 - i) * 8;
			result |= (long) (b[i] & 0x000000FF) << shift;
		}
		return result;
	}

	/**
	 * Convert the given long to an 8-byte array
	 * 
	 * @param l
	 *            A 'long'
	 * 
	 * @return An 8-byte array in big endian (MSB) ordering
	 */
	public static byte[] convertLongToByteArrayBigEndian(long l) {
		byte[] result = new byte[Long.SIZE / 8];
		for (int j = 0; j < result.length; j++) {
			int shift = (result.length - 1 - j) * 8;
			result[j] = (byte) ((l >> shift) & 0xFF);
		}
		return result;
	}

	/**
	 * Copy the entire content of an InputStream into an OutputStream and close
	 * only the input stream.
	 * 
	 * @param in
	 *            The InputStream to read data from
	 * @param out
	 *            The OutputStream to write data to
	 * 
	 * @throws IOException
	 *             I/O exception from read or write
	 */
	public static void copyWholeStreamAndCloseInput(InputStream in, OutputStream out) throws IOException {
		try {
			readFromAndWriteTo(in, out);
		} finally {
			in.close();
		}
	}

	/**
	 * Copy the entire content of an InputStream into an OutputStream and close
	 * both streams.
	 * 
	 * @param in
	 *            The InputStream to read data from
	 * @param out
	 *            The OutputStream to write data to
	 * 
	 * @throws IOException
	 *             I/O exception from read or write
	 */
	public static void copyWholeStreamAndClose(InputStream in, OutputStream out) throws IOException {
		try {
			copyWholeStreamAndCloseInput(in, out);
		} finally {
			out.close();
		}
	}

	private static void readFromAndWriteTo(InputStream in, OutputStream out) throws IOException {
		byte[] buf = new byte[EIGHT_KILO];
		int bytesRead = in.read(buf);
		while (bytesRead >= 0) {
			out.write(buf, 0, bytesRead);
			bytesRead = in.read(buf);
		}
	}
}