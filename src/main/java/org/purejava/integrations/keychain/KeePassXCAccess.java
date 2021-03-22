package org.purejava.integrations.keychain;

import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.cryptomator.integrations.keychain.KeychainAccessProvider;
import org.purejava.KeepassProxyAccess;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class KeePassXCAccess implements KeychainAccessProvider {

	private static final Logger LOG = LoggerFactory.getLogger(KeePassXCAccess.class);
	private KeepassProxyAccess proxy;

	public KeePassXCAccess() {
		proxy = new KeepassProxyAccess();
	}

	@Override
	public boolean isSupported() { return proxy.connect();}

	@Override
	public boolean isLocked() {	return proxy.connectionAvailable();	}

	@Override
	public void storePassphrase(String vault, CharSequence password) throws KeychainAccessException {
		vault = "https://" + vault;
		if (!proxy.connectionAvailable()) {
			throw new KeychainAccessException("Storing of the passphrase failed");
		}
		if (!proxy.loginExists(vault, null, false, List.of(proxy.exportConnection()), password.toString())
		&& !proxy.setLogin(vault, null, null, "Vault", password.toString(), "default", "default", "default")) {
			throw new KeychainAccessException("Storing of the passphrase failed");
		}
	}

	@Override
	public char[] loadPassphrase(String vault) throws KeychainAccessException {
		if (!proxy.connectionAvailable()) {
			throw new KeychainAccessException("Loading of the passphrase failed");
		}
		vault = "https://" + vault;
		Map<String, Object> answer = proxy.getLogins(vault, null, false, List.of(proxy.exportConnection()));
		if (answer.isEmpty()) {
			throw new KeychainAccessException("Loading of the passphrase failed");
		}
		List<Object> array = (ArrayList<Object>) answer.get("entries");
		Map<String, Object> credentials = (HashMap<String, Object>) array.get(0);
		String password;
		if (credentials.get("password") != null) {
			password = (String) credentials.get("password");
			return password.toCharArray();
		} else {
			throw new KeychainAccessException("Loading of the passphrase failed");
		}
	}

	@Override
	public void deletePassphrase(String s) throws KeychainAccessException {

	}

	@Override
	public void changePassphrase(String s, CharSequence charSequence) throws KeychainAccessException {

	}
}
