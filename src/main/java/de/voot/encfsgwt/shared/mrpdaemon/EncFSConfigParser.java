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

import com.google.gwt.core.client.Callback;
import com.google.gwt.xml.client.Document;
import com.google.gwt.xml.client.Node;
import com.google.gwt.xml.client.NodeList;
import com.google.gwt.xml.client.XMLParser;

import de.voot.encfsgwt.shared.jre.InputStream;
import de.voot.encfsgwt.shared.util.StreamUtil;


/**
 * Parser methods that read and interpret EncFS configuration files.
 */
public class EncFSConfigParser {

	private static String getNodeValue(Node n) {
		return n.getChildNodes().item(0).getNodeValue();
	}

	/**
	 * Parse the configuration file residing on an EncFSFileProvider with the
	 * given path
	 * 
	 * @param fileProvider
	 *            File provider to access the config file
	 * @param path
	 *            Path of the config file in the file provider's notation
	 * @return An EncFSConfig object representing the parsing result
	 */
	public static void parseConfig(final EncFSFileProvider fileProvider, final String path, final Callback<EncFSConfig, Exception> callback) {
		String configPath = fileProvider.getFilesystemRootPath() + path;
		fileProvider.exists(configPath, new Callback<Boolean, IOException>() {
			@Override
			public void onFailure(IOException reason) {
				callback.onFailure(reason);
			}

			@Override
			public void onSuccess(Boolean result) {
				if (!result) {
					callback.onFailure(new EncFSInvalidConfigException("No EncFS configuration file found"));
					return;
				}

				// Parse the configuration file
				fileProvider.openInputStream(fileProvider.getFilesystemRootPath() + path, new Callback<InputStream, IOException>() {
					@Override
					public void onFailure(IOException reason) {
						callback.onFailure(reason);
					}

					@Override
					public void onSuccess(InputStream result) {
						try {
							EncFSConfig config = EncFSConfigParser.parseFile(result);
							config.validate();

							callback.onSuccess(config);
						} catch (Exception e) {
							callback.onFailure(e);
						}
					}
				});
			}
		});
	}

	/**
	 * Parse the given configuration file from a stream
	 * 
	 * @param inputStream
	 *            InputStream for the config file
	 * @return An EncFSConfig object containing the configuration data
	 *         interpreted from the given file.
	 * @throws EncFSInvalidConfigException
	 * @throws IOException
	 */
	private static EncFSConfig parseFile(InputStream inputStream) throws EncFSInvalidConfigException, IOException {
		EncFSConfig config = EncFSConfigFactory.createDefault();

		String data = StreamUtil.readToString(inputStream);
		Document doc = XMLParser.parse(data);

		NodeList cfgNodeList = doc.getElementsByTagName("cfg").item(0).getChildNodes();

		if (cfgNodeList.getLength() == 0) {
			throw new EncFSInvalidConfigException("<cfg> element not present in config file");
		}

		for (int i = 0; i < cfgNodeList.getLength(); i++) {
			Node cfgNode = cfgNodeList.item(i);

			if (cfgNode.getNodeType() == Node.ELEMENT_NODE) {
				if (cfgNode.getNodeName().equals("nameAlg")) {
					NodeList nameAlgNodeList = cfgNode.getChildNodes();
					for (int j = 0; j < nameAlgNodeList.getLength(); j++) {
						Node nameAlgChildNode = nameAlgNodeList.item(j);
						if (nameAlgChildNode.getNodeName().equals("name")) {
							String algName = getNodeValue(nameAlgChildNode);
							try {
								config.setFilenameAlgorithm(EncFSFilenameEncryptionAlgorithm.parse(algName));
							} catch (IllegalArgumentException e) {
								throw new EncFSInvalidConfigException("Unknown name algorithm in config file: " + algName);
							}
						}
					}
				} else if (cfgNode.getNodeName().equals("keySize")) {
					config.setVolumeKeySizeInBits(Integer.parseInt(getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("blockSize")) {
					config.setEncryptedFileBlockSizeInBytes(Integer.parseInt(getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("uniqueIV")) {
					config.setUseUniqueIV(Integer.parseInt(getNodeValue(cfgNode)) == 1);
				} else if (cfgNode.getNodeName().equals("chainedNameIV")) {
					config.setChainedNameIV(Integer.parseInt(getNodeValue(cfgNode)) == 1);
				} else if (cfgNode.getNodeName().equals("allowHoles")) {
					config.setHolesAllowedInFiles(Integer.parseInt(getNodeValue(cfgNode)) == 1);
				} else if (cfgNode.getNodeName().equals("encodedKeySize")) {
					config.setEncodedKeyLengthInBytes(Integer.parseInt(getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("encodedKeyData")) {
					config.setBase64EncodedVolumeKey(getNodeValue(cfgNode));
				} else if (cfgNode.getNodeName().equals("saltLen")) {
					config.setSaltLengthBytes(Integer.parseInt(getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("saltData")) {
					config.setBase64Salt(getNodeValue(cfgNode));
				} else if (cfgNode.getNodeName().equals("kdfIterations")) {
					config.setIterationForPasswordKeyDerivationCount(Integer.parseInt(getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("blockMACBytes")) {
					config.setNumberOfMACBytesForEachFileBlock(Integer.parseInt(getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("blockMACRandBytes")) {
					config.setNumberOfRandomBytesInEachMACHeader(Integer.parseInt(getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("externalIVChaining")) {
					config.setSupportedExternalIVChaining(Integer.parseInt(getNodeValue(cfgNode)) == 1);
				}
			}
		}

		return config;
	}
}