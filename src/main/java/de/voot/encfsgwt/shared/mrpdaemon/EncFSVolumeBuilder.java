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

import java.io.IOException;

import com.google.gwt.core.client.Callback;

import de.voot.encfsgwt.shared.crypto.SecureRandom;


/**
 * Class for building EncFSVolume objects and writing new volume files to file
 * providers.
 * 
 * Usage (in order):
 * 
 * [Required] .withFileProvider(provider) OR .withRootPath(rootPath)
 * 
 * [Optional] .withConfig(config) AND/OR .withPbkdfProvider(pbkdf2provider)
 * 
 * [Required] .withPassword(password)
 * 
 * 
 * Volume building methods: <br>
 * .writeVolumeConfig() - Write volume configuration file to the file provider <br>
 * .buildVolume() - Return an EncFSVolume
 */
public final class EncFSVolumeBuilder {

	public static class FileProviderBuilder {

		private final EncFSVolume volume;

		public FileProviderBuilder(EncFSVolume volume, EncFSFileProvider fileProvider) {
			this.volume = volume;
			volume.setFileProvider(fileProvider);
		}

		public void withConfig(EncFSConfig config, final Callback<ConfigBuilder, Exception> callback) {
			ConfigBuilder.getInstance(volume, config, callback);
		}

		public void withPbkdf2Provider(final EncFSPBKDF2Provider pbkdf2Provider, final Callback<Pbkdf2ProviderBuilder, Exception> callback) {
			ConfigBuilder.getInstance(volume, new Callback<ConfigBuilder, Exception>() {
				@Override
				public void onFailure(Exception reason) {
					callback.onFailure(reason);
				}

				@Override
				public void onSuccess(ConfigBuilder result) {
					callback.onSuccess(result.withPbkdf2Provider(pbkdf2Provider));
				}
			});
		}

		public void withPassword(final String password, final Callback<PasswordBuilder, Exception> callback) {
			withPbkdf2Provider(null, new Callback<EncFSVolumeBuilder.Pbkdf2ProviderBuilder, Exception>() {
				@Override
				public void onFailure(Exception reason) {
					callback.onFailure(reason);
				}

				@Override
				public void onSuccess(Pbkdf2ProviderBuilder result) {
					callback.onSuccess(result.withPassword(password));
				}
			});
		}

		public void withDerivedPassword(final byte[] derivedPassword, final Callback<PasswordBuilder, Exception> callback) {
			withPbkdf2Provider(null, new Callback<EncFSVolumeBuilder.Pbkdf2ProviderBuilder, Exception>() {
				@Override
				public void onFailure(Exception reason) {
					callback.onFailure(reason);
				}

				@Override
				public void onSuccess(Pbkdf2ProviderBuilder result) {
					callback.onSuccess(result.withDerivedPassword(derivedPassword));
				}
			});
		}
	}

	public static class ConfigBuilder {

		private final EncFSVolume volume;

		private ConfigBuilder(EncFSVolume volume) {
			this.volume = volume;
		}

		public static void getInstance(final EncFSVolume volume, EncFSConfig config, final Callback<ConfigBuilder, Exception> callback) {
			volume.setVolumeConfig(config);
			callback.onSuccess(new ConfigBuilder(volume));
		}

		public static void getInstance(final EncFSVolume volume, final Callback<ConfigBuilder, Exception> callback) {
			EncFSFileProvider fileProvider = volume.getFileProvider();
			EncFSConfigParser.parseConfig(fileProvider, EncFSVolume.CONFIG_FILE_NAME, new Callback<EncFSConfig, Exception>() {
				@Override
				public void onFailure(Exception reason) {
					callback.onFailure(reason);
				}

				@Override
				public void onSuccess(EncFSConfig volumeConfiguration) {
					volume.setVolumeConfig(volumeConfiguration);
					callback.onSuccess(new ConfigBuilder(volume));
				}
			});
		}

		public Pbkdf2ProviderBuilder withPbkdf2Provider(EncFSPBKDF2Provider provider) {
			return new Pbkdf2ProviderBuilder(volume, provider);
		}

		public PasswordBuilder withPassword(String password) throws EncFSCorruptDataException, EncFSInvalidPasswordException, EncFSInvalidConfigException,
				EncFSUnsupportedException, IOException {
			return withPbkdf2Provider(null).withPassword(password);
		}

		public PasswordBuilder withDerivedPassword(byte[] derivedPassword) throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException,
				EncFSCorruptDataException, EncFSInvalidPasswordException {
			return withPbkdf2Provider(null).withDerivedPassword(derivedPassword);
		}
	}

	public static class Pbkdf2ProviderBuilder {

		private final EncFSVolume volume;
		private final EncFSPBKDF2Provider provider;

		public Pbkdf2ProviderBuilder(EncFSVolume volume, EncFSPBKDF2Provider provider) {
			this.volume = volume;
			this.provider = provider;
		}

		public PasswordBuilder withPassword(String password) {
			return new PasswordBuilder(volume, password, provider);
		}

		public PasswordBuilder withDerivedPassword(byte[] derivedPassword) {
			return new PasswordBuilder(volume, derivedPassword);
		}
	}

	public static class PasswordBuilder {

		private final EncFSVolume volume;
		private final EncFSPBKDF2Provider provider;
		private final String password;

		public PasswordBuilder(EncFSVolume volume, byte[] derivedPassword) {
			this.volume = volume;
			this.provider = null;
			this.password = null;
			volume.setPasswordDerivedKeyData(derivedPassword);

		}

		public PasswordBuilder(EncFSVolume volume, String password, EncFSPBKDF2Provider provider) {
			this.volume = volume;
			this.password = password;
			this.provider = provider;
		}

		/**
		 * Creates a new object representing an existing EncFS volume
		 * 
		 * @throws EncFSInvalidPasswordException
		 *             Given password is incorrect
		 * @throws EncFSCorruptDataException
		 *             Corrupt data detected (checksum error)
		 * @throws EncFSInvalidConfigException
		 *             Configuration file format not recognized
		 * @throws EncFSUnsupportedException
		 *             Unsupported EncFS version or options
		 * @throws IOException
		 *             File provider returned I/O error
		 */
		public void buildVolume(final Callback<EncFSVolume, Exception> callback) throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException,
				EncFSInvalidPasswordException, EncFSCorruptDataException {
			EncFSConfig config = volume.getConfig();
			if (password != null) {
				byte[] derivedPassword = VolumeKey.derivePasswordKey(config, password, provider);
				volume.setPasswordDerivedKeyData(derivedPassword);
			}
			volume.readConfigAndInitVolume(new Callback<Void, Exception>() {
				@Override
				public void onFailure(Exception reason) {
					callback.onFailure(reason);
				}

				@Override
				public void onSuccess(Void result) {
					callback.onSuccess(volume);
				}
			});
		}

		/**
		 * Writes EncFS volume configuration to the file provider
		 * 
		 * @throws EncFSInvalidPasswordException
		 *             Given password is incorrect
		 * @throws EncFSCorruptDataException
		 *             Corrupt data detected (checksum error)
		 * @throws EncFSInvalidConfigException
		 *             Configuration file format not recognized
		 * @throws EncFSUnsupportedException
		 *             Unsupported EncFS version or options
		 * @throws IOException
		 *             File provider returned I/O error
		 */
		public void writeVolumeConfig() throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException, EncFSCorruptDataException {
			EncFSConfig config = volume.getConfig();
			EncFSFileProvider fileProvider = volume.getFileProvider();

			// Create a random volume VolumeCryptKey + IV pair
			byte[] randVolKey = new byte[config.getVolumeKeySizeInBits() / 8 + EncFSVolume.IV_LENGTH_IN_BYTES];
			new SecureRandom().nextBytes(randVolKey);

			VolumeKey.encodeVolumeKey(config, password, randVolKey, provider);
			EncFSConfigWriter.writeConfig(fileProvider, config);
		}
	}

	public FileProviderBuilder withFileProvider(EncFSFileProvider fileProvider) {
		return new FileProviderBuilder(new EncFSVolume(), fileProvider);
	}
}
