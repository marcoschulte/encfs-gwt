/*
 * Copyright (c) 1994, 2006, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package de.voot.encfsgwt.shared.jre;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import de.voot.encfsgwt.shared.util.ArrayUtil;

/**
 * This class implements an output stream in which the data is written into a
 * byte array. The buffer automatically grows as data is written to it. The data
 * can be retrieved using <code>toByteArray()</code> and <code>toString()</code>
 * .
 * <p>
 * Closing a <tt>ByteArrayOutputStream</tt> has no effect. The methods in this
 * class can be called after the stream has been closed without generating an
 * <tt>IOException</tt>.
 * 
 * @author Arthur van Hoff
 * @since JDK1.0
 */

public class ByteArrayOutputStream extends OutputStream {

	/**
	 * The buffer where data is stored.
	 */
	protected byte buf[];

	/**
	 * The number of valid bytes in the buffer.
	 */
	protected int count;

	/**
	 * Creates a new byte array output stream. The buffer capacity is initially
	 * 32 bytes, though its size increases if necessary.
	 */
	public ByteArrayOutputStream() {
		this(32);
	}

	/**
	 * Creates a new byte array output stream, with a buffer capacity of the
	 * specified size, in bytes.
	 * 
	 * @param size
	 *            the initial size.
	 * @exception IllegalArgumentException
	 *                if size is negative.
	 */
	public ByteArrayOutputStream(int size) {
		if (size < 0) {
			throw new IllegalArgumentException("Negative initial size: " + size);
		}
		buf = new byte[size];
	}

	/**
	 * Writes the specified byte to this byte array output stream.
	 * 
	 * @param b
	 *            the byte to be written.
	 */
	@Override
	public synchronized void write(int b) {
		int newcount = count + 1;
		if (newcount > buf.length) {
			buf = ArrayUtil.copyOf(buf, Math.max(buf.length << 1, newcount));
		}
		buf[count] = (byte) b;
		count = newcount;
	}

	/**
	 * Writes <code>len</code> bytes from the specified byte array starting at
	 * offset <code>off</code> to this byte array output stream.
	 * 
	 * @param b
	 *            the data.
	 * @param off
	 *            the start offset in the data.
	 * @param len
	 *            the number of bytes to write.
	 */
	@Override
	public synchronized void write(byte b[], int off, int len) {
		if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length) || ((off + len) < 0)) {
			throw new IndexOutOfBoundsException();
		} else if (len == 0) {
			return;
		}
		int newcount = count + len;
		if (newcount > buf.length) {
			buf = ArrayUtil.copyOf(buf, Math.max(buf.length << 1, newcount));
		}
		System.arraycopy(b, off, buf, count, len);
		count = newcount;
	}

	/**
	 * Writes the complete contents of this byte array output stream to the
	 * specified output stream argument, as if by calling the output stream's
	 * write method using <code>out.write(buf, 0, count)</code>.
	 * 
	 * @param out
	 *            the output stream to which to write the data.
	 * @exception IOException
	 *                if an I/O error occurs.
	 */
	public synchronized void writeTo(OutputStream out) throws IOException {
		out.write(buf, 0, count);
	}

	/**
	 * Resets the <code>count</code> field of this byte array output stream to
	 * zero, so that all currently accumulated output in the output stream is
	 * discarded. The output stream can be used again, reusing the already
	 * allocated buffer space.
	 * 
	 * @see java.io.ByteArrayInputStream#count
	 */
	public synchronized void reset() {
		count = 0;
	}

	/**
	 * Creates a newly allocated byte array. Its size is the current size of
	 * this output stream and the valid contents of the buffer have been copied
	 * into it.
	 * 
	 * @return the current contents of this output stream, as a byte array.
	 * @see java.io.ByteArrayOutputStream#size()
	 */
	public synchronized byte toByteArray()[] {
		return ArrayUtil.copyOf(buf, count);
	}

	/**
	 * Returns the current size of the buffer.
	 * 
	 * @return the value of the <code>count</code> field, which is the number of
	 *         valid bytes in this output stream.
	 * @see java.io.ByteArrayOutputStream#count
	 */
	public synchronized int size() {
		return count;
	}

	/**
	 * Converts the buffer's contents into a string decoding bytes using the
	 * platform's default character set. The length of the new <tt>String</tt>
	 * is a function of the character set, and hence may not be equal to the
	 * size of the buffer.
	 * 
	 * <p>
	 * This method always replaces malformed-input and unmappable-character
	 * sequences with the default replacement string for the platform's default
	 * character set. The {@linkplain java.nio.charset.CharsetDecoder} class
	 * should be used when more control over the decoding process is required.
	 * 
	 * @return String decoded from the buffer's contents.
	 * @since JDK1.1
	 */
	@Override
	public synchronized String toString() {
		return new String(buf, 0, count);
	}

	/**
	 * Converts the buffer's contents into a string by decoding the bytes using
	 * the specified {@link java.nio.charset.Charset charsetName}. The length of
	 * the new <tt>String</tt> is a function of the charset, and hence may not
	 * be equal to the length of the byte array.
	 * 
	 * <p>
	 * This method always replaces malformed-input and unmappable-character
	 * sequences with this charset's default replacement string. The
	 * {@link java.nio.charset.CharsetDecoder} class should be used when more
	 * control over the decoding process is required.
	 * 
	 * @param charsetName
	 *            the name of a supported {@linkplain java.nio.charset.Charset
	 *            </code>charset<code>}
	 * @return String decoded from the buffer's contents.
	 * @exception UnsupportedEncodingException
	 *                If the named charset is not supported
	 * @since JDK1.1
	 */
	public synchronized String toString(String charsetName) throws UnsupportedEncodingException {
		return new String(buf, 0, count, charsetName);
	}

	/**
	 * Closing a <tt>ByteArrayOutputStream</tt> has no effect. The methods in
	 * this class can be called after the stream has been closed without
	 * generating an <tt>IOException</tt>.
	 * <p>
	 * 
	 */
	@Override
	public void close() throws IOException {
	}

}
