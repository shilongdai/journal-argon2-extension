package net.viperfish.extension.argon2;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import net.viperfish.journal.framework.AuthenticationManager;
import net.viperfish.journal.framework.ConfigMapping;
import net.viperfish.journal.framework.Configuration;
import net.viperfish.journal.framework.errors.FailToLoadCredentialException;
import net.viperfish.journal.framework.provider.AuthProvider;
import ro.fortsoft.pf4j.Extension;

@Extension
public final class Argon2Provider implements AuthProvider {

	private Argon2AuthenticationManager auth;
	private File passwdFile;

	private void lazyLoad() throws FailToLoadCredentialException {
		if (auth == null) {
			auth = new Argon2AuthenticationManager(passwdFile);
			auth.load();
		}
		return;
	}

	public Argon2Provider() {
		File dataDir;
		File dataRoot;
		String portable = Configuration.getString(ConfigMapping.PORTABLE);
		if (portable == null || Boolean.valueOf(portable).booleanValue() == false) {
			dataRoot = new File(System.getProperty("user.home"), ".vsDiary");
		} else {
			dataRoot = new File(".");
		}
		dataDir = new File(dataRoot, "secure");
		try {
			Files.createDirectories(dataDir.toPath());
			passwdFile = new File(dataDir, "passwd");
			if (!passwdFile.exists()) {
				Files.createFile(passwdFile.toPath());
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void delete() {
		try {
			Files.deleteIfExists(passwdFile.toPath());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void dispose() {
		auth = null;

	}

	@Override
	public String getDefaultInstance() {
		return "Argon2";
	}

	@Override
	public AuthenticationManager getInstance() {
		try {
			lazyLoad();
		} catch (FailToLoadCredentialException e) {
			throw new RuntimeException(e);
		}
		return auth;
	}

	@Override
	public AuthenticationManager getInstance(String arg0) {
		if (arg0.equals("Argon2")) {
			try {
				lazyLoad();
			} catch (FailToLoadCredentialException e) {
				throw new RuntimeException(e);
			}
			return auth;
		}
		return null;
	}

	@Override
	public String getName() {
		return "Argon2Provider";
	}

	@Override
	public String[] getSupported() {
		return new String[] { "Argon2" };
	}

	@Override
	public void initDefaults() {

	}

	@Override
	public AuthenticationManager newInstance() {
		return new Argon2AuthenticationManager(passwdFile);
	}

	@Override
	public AuthenticationManager newInstance(String arg0) {
		if (arg0.equals("Argon2")) {
			return new Argon2AuthenticationManager(passwdFile);
		} else {
			return null;
		}
	}

	@Override
	public void refresh() {
		this.auth = null;
	}

	@Override
	public void registerConfig() {
	}

	@Override
	public void setDefaultInstance(String arg0) {
	}

}
