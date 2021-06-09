package org.purejava.integrations.keychain;

import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.cryptomator.integrations.keychain.KeychainAccessProvider;
import org.purejava.KeepassProxyAccess;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


public class KeePassXCAccess implements KeychainAccessProvider {

	private KeepassProxyAccess proxy;
	private final String URL_SCHEME = "https://";
	private final String APP_NAME = "Cryptomator";

	public KeePassXCAccess() {
		proxy = new KeepassProxyAccess();
	}

	@Override
	public String displayName() { return "KeePassXC"; }

	@Override
	public boolean isSupported() { return proxy.connect(); }

	@Override
	public boolean isLocked() { return proxy.getDatabasehash().isEmpty(); }

	private void ensureAssociation() throws KeychainAccessException {
		// Proxy needs association
		if (!proxy.connectionAvailable() && !proxy.associate()) {
			throw new KeychainAccessException("Association with KeePassXC database failed");
		}
	}

	public String unlock() { return proxy.getDatabasehash(true); }

	@Override
	public void storePassphrase(String vault, CharSequence password) throws KeychainAccessException {
		if (isLocked()) {
			throw new KeychainAccessException("Failed to store password. KeePassXC database is locked. Needs to be unlocked first");
		}
		ensureAssociation();
		var urlVault = URL_SCHEME + vault;
		var group = proxy.createNewGroup(APP_NAME); // Store passphrase in group APP_NAME
		if (!proxy.loginExists(urlVault, null, false, List.of(proxy.exportConnection()), password.toString())
		&& !proxy.setLogin(urlVault, null, null, "Vault", password.toString(), APP_NAME, group.get("uuid"), null)) {
			throw new KeychainAccessException("Storing of the password failed");
		}
	}

	@Override
	public char[] loadPassphrase(String vault) throws KeychainAccessException {
		if (isLocked()) {
			throw new KeychainAccessException("Failed to load password. KeePassXC database is locked. Needs to be unlocked first");
		}
		ensureAssociation();
		var urlVault = URL_SCHEME + vault;
		var answer = proxy.getLogins(urlVault, null, false, List.of(proxy.exportConnection()));
		if (answer.isEmpty() || null == answer.get("entries")) {
			throw new KeychainAccessException("No password found for vault " + urlVault.substring(URL_SCHEME.length()));
		}
		var array = (ArrayList<Object>) answer.get("entries");
		var credentials = (HashMap<String, Object>) array.get(0);
		if (credentials.get("password") != null) {
			var password = (String) credentials.get("password");
			return password.toCharArray();
		} else {
			throw new KeychainAccessException("Loading of the password failed");
		}
	}

	@Override
	public void deletePassphrase(String vault) throws KeychainAccessException {
		throw new KeychainAccessException("KeePassXC does not support deleting from Cryptomator. Please use the KeePassXC app UI.");
	}

	@Override
	public void changePassphrase(String vault, CharSequence password) throws KeychainAccessException {
		if (isLocked()) {
			throw new KeychainAccessException("Failed to change password. KeePassXC database is locked. Needs to be unlocked first");
		}
		ensureAssociation();
		var urlVault = URL_SCHEME + vault;
		var group = proxy.createNewGroup(APP_NAME); // Update passphrase in group APP_NAME
		var answer = proxy.getLogins(urlVault, null, false, List.of(proxy.exportConnection()));
		if (answer.isEmpty() || null == answer.get("entries")) {
			throw new KeychainAccessException("No password found for vault " + urlVault.substring(URL_SCHEME.length()));
		}
		var array = (ArrayList<Object>) answer.get("entries");
		var credentials = (HashMap<String, Object>) array.get(0);
		var uuid = (String) credentials.get("uuid");
		if (!proxy.setLogin(urlVault, null, null, "Vault", password.toString(), APP_NAME, group.get("uuid"), uuid)) {
			throw new KeychainAccessException("Changing the password failed");
		}
	}
}
