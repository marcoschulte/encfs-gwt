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
package de.voot.encfsgwt.shared.crypto;

import de.voot.encfsgwt.shared.jre.SecretKey;

public class PBKDF2SHA1SecretKey implements SecretKey {

	private static final long serialVersionUID = -3322686031873211670L;

	private final byte[] encoded;

	public PBKDF2SHA1SecretKey(byte[] encoded) {
		this.encoded = encoded;
	}

	@Override
	public String getAlgorithm() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return encoded;
	}

}
