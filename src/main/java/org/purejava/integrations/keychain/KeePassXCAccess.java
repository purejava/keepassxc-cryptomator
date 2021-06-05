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
	private final String URL_SCHEME = "https://";

	public KeePassXCAccess() {
		proxy = new KeepassProxyAccess();
	}

	@Override
	public boolean isSupported() { return proxy.connect(); }

	@Override
	public boolean isLocked() { return proxy.getDatabasehash().isEmpty(); }

	@Override
	public boolean needsAssociation() { return !proxy.connectionAvailable(); }

	@Override
	public boolean associate() { return proxy.associate(); }

	public String unlock() { return proxy.getDatabasehash(true); }

	@Override
	public void storePassphrase(String vault, CharSequence password) throws KeychainAccessException {
		vault = URL_SCHEME + vault;
		if (isLocked()) {
			throw new KeychainAccessException("Storing of the passphrase failed");
		}
		if (!proxy.loginExists(vault, null, false, List.of(proxy.exportConnection()), password.toString())
		&& !proxy.setLogin(vault, null, null, "Vault", password.toString(), "default", "default", "default")) {
			throw new KeychainAccessException("Storing of the passphrase failed");
		}
	}

	@Override
	public char[] loadPassphrase(String vault) throws KeychainAccessException {
		if (isLocked()) {
			throw new KeychainAccessException("Loading of the passphrase failed");
		}
		vault = URL_SCHEME + vault;
		var answer = proxy.getLogins(vault, null, false, List.of(proxy.exportConnection()));
		if (answer.isEmpty() || null == answer.get("entries")) {
			throw new KeychainAccessException("Loading of the passphrase failed");
		}
		var array = (ArrayList<Object>) answer.get("entries");
		var credentials = (HashMap<String, Object>) array.get(0);
		if (credentials.get("password") != null) {
			var password = (String) credentials.get("password");
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
