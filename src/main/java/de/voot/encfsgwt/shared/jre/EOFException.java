/*
 * Copyright (c) 1995, 2000, Oracle and/or its affiliates. All rights reserved.
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

/**
 * Signals that an end of file or end of stream has been reached unexpectedly
 * during input.
 * <p>
 * This exception is mainly used by data input streams to signal end of stream.
 * Note that many other input operations return a special value on end of stream
 * rather than throwing an exception.
 * <p>
 * 
 * @author Frank Yellin
 * @see java.io.DataInputStream
 * @see java.io.IOException
 * @since JDK1.0
 */
public class EOFException extends IOException {
	/**
	 * Constructs an <code>EOFException</code> with <code>null</code> as its
	 * error detail message.
	 */
	public EOFException() {
		super();
	}

	/**
	 * Constructs an <code>EOFException</code> with the specified detail
	 * message. The string <code>s</code> may later be retrieved by the
	 * <code>{@link java.lang.Throwable#getMessage}</code> method of class
	 * <code>java.lang.Throwable</code>.
	 * 
	 * @param s
	 *            the detail message.
	 */
	public EOFException(String s) {
		super(s);
	}
}
