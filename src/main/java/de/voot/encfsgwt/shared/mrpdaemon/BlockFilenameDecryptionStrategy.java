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
import de.voot.encfsgwt.shared.util.ArrayUtil;

// Implementation of block filename decryption strategy
class BlockFilenameDecryptionStrategy extends BasicFilenameDecryptionStrategy {

	BlockFilenameDecryptionStrategy(EncFSVolume volume, String volumePath) {
		super(volume, volumePath, EncFSFilenameEncryptionAlgorithm.BLOCK);
	}

	// Block decryption
	@Override
	protected byte[] decryptConcrete(EncFSVolume volume, byte[] encFileName, byte[] fileIv) throws EncFSCorruptDataException {
		try {
			return BlockCrypto.blockDecrypt(volume, fileIv, encFileName);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSCorruptDataException(e);
		} catch (IllegalBlockSizeException e) {
			throw new EncFSCorruptDataException(e);
		} catch (BadPaddingException e) {
			throw new EncFSCorruptDataException(e);
		}
	}

	// Remove padding after decryption
	@Override
	protected String decryptPost(byte[] fileName) {
		int padLen = fileName[fileName.length - 1];

		return new String(ArrayUtil.copyOfRange(fileName, 0, fileName.length - padLen));
	}
}
