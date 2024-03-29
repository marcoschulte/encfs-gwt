/*
 * EncFS Java Library
 * Copyright (C) 2013 encfs-java authors
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

import de.voot.encfsgwt.shared.jre.BadPaddingException;
import de.voot.encfsgwt.shared.jre.IllegalBlockSizeException;
import de.voot.encfsgwt.shared.jre.InvalidAlgorithmParameterException;

//Implementation of block filename decryption strategy
public class StreamFilenameEncryptionStrategy extends BasicFilenameEncryptionStrategy {

	public StreamFilenameEncryptionStrategy(EncFSVolume volume, String volumePath) {
		super(volume, volumePath, EncFSFilenameEncryptionAlgorithm.STREAM);
	}

	// Stream encryption
	@Override
	protected byte[] encryptConcrete(EncFSVolume volume, byte[] paddedDecFileName, byte[] fileIv) throws EncFSCorruptDataException {
		try {
			return StreamCrypto.streamEncrypt(volume, fileIv, paddedDecFileName);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSCorruptDataException(e);
		} catch (IllegalBlockSizeException e) {
			throw new EncFSCorruptDataException(e);
		} catch (BadPaddingException e) {
			throw new EncFSCorruptDataException(e);
		} catch (EncFSUnsupportedException e) {
			throw new EncFSCorruptDataException(e);
		}
	}

	@Override
	protected byte[] getPaddedDecFilename(byte[] decFileName) {
		return decFileName;
	}
}
