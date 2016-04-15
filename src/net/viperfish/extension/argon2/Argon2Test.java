package net.viperfish.extension.argon2;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import net.viperfish.journal.framework.AuthTest;
import net.viperfish.journal.framework.AuthenticationManager;

public class Argon2Test extends AuthTest {

	@Override
	protected AuthenticationManager getAuth(File arg0) {

		File passwdFile = new File(arg0, "passwd");
		try {
			Files.createDirectories(arg0.toPath());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return new Argon2AuthenticationManager(passwdFile);
	}

}
