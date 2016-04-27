package net.viperfish.extension.argon2;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import net.viperfish.framework.file.IOFile;
import net.viperfish.framework.file.TextIOStreamHandler;
import net.viperfish.journal.framework.AuthenticationManager;
import net.viperfish.journal.framework.errors.CannotClearPasswordException;
import net.viperfish.journal.framework.errors.FailToLoadCredentialException;
import net.viperfish.journal.framework.errors.FailToStoreCredentialException;

final class Argon2AuthenticationManager implements AuthenticationManager {

	private IOFile passwdFile;
	private Argon2 hasher;
	private String password;
	private String argon2Hash;

	public Argon2AuthenticationManager(File passwdFile) {
		this.passwdFile = new IOFile(passwdFile, new TextIOStreamHandler());
		hasher = Argon2Factory.create();
	}

	@Override
	public synchronized void clear() throws CannotClearPasswordException {
		try {
			passwdFile.write("", StandardCharsets.US_ASCII);
		} catch (IOException e) {
			CannotClearPasswordException cp = new CannotClearPasswordException("Cannot clear password in "
					+ passwdFile.getFile().getAbsolutePath() + " message:" + e.getMessage());
			cp.initCause(e);
			throw cp;
		}

	}

	@Override
	public synchronized String getPassword() {
		return password;
	}

	@Override
	public synchronized void load() throws FailToLoadCredentialException {
		try {
			argon2Hash = passwdFile.read(StandardCharsets.US_ASCII);
		} catch (IOException e) {
			FailToLoadCredentialException fl = new FailToLoadCredentialException("Cannot load argon2 hash from file "
					+ passwdFile.getFile().getAbsolutePath() + ": " + e.getMessage());
			fl.initCause(e);
			throw fl;
		}
	}

	@Override
	public synchronized void setPassword(String arg0) throws FailToStoreCredentialException {
		argon2Hash = hasher.hash(32768, 500, 2, arg0);
		this.password = arg0;
		try {
			passwdFile.write(argon2Hash, StandardCharsets.US_ASCII);
		} catch (IOException e) {
			FailToStoreCredentialException fc = new FailToStoreCredentialException(
					"Cannot store argon2 hash to:" + passwdFile + " message:" + e.getMessage());
			fc.initCause(e);
			throw fc;
		}
	}

	@Override
	public synchronized boolean verify(String arg0) {
		boolean result = hasher.verify(argon2Hash, arg0);
		System.out.println("expected:" + argon2Hash);
		if (result) {
			this.password = arg0;
		}
		return result;

	}

}
