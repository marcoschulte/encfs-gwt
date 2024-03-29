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

public class EncFSInvalidConfigException extends EncFSException {

	private static final long serialVersionUID = 1L;

	public EncFSInvalidConfigException(String message) {
		super(message);
	}

	public EncFSInvalidConfigException(Throwable cause) {
		super(cause);
	}

}
