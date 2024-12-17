package org.purejava.integrations.keychain;

import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.cryptomator.integrations.keychain.KeychainAccessProvider;
import org.purejava.KeepassProxyAccess;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


public class KeePassXCAccess implements KeychainAccessProvider {

	private static final Logger LOG = LoggerFactory.getLogger(KeePassXCAccess.class);

	private final KeepassProxyAccess proxy;
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
	public boolean isLocked() { return proxy.isDatabaseLocked(); }

	/**
	 * Called on every request sent to the KeePassXC back end to associate Cryptomator and KeePassXC,
	 * in case this did not happen before.
	 *
	 * @throws KeychainAccessException It was impossible to associate KeePassXC with Cryptomator.
	 */
	private void ensureAssociation() throws KeychainAccessException {
		// Proxy needs association, in case !proxy.connectionAvailable()
		if (!proxy.connectionAvailable() && !proxy.associate()) {
			throw new KeychainAccessException("Association with KeePassXC database failed");
		}
	}

	/**
	 * Request for receiving the database hash (SHA256) of the current active KeePassXC database.
	 * Sent together with a request to unlock the KeePassXC databasee, which is the sole reason to
	 * define this method.
	 *
	 * @return The database hash of the current active KeePassXC database.
	 */
	public String unlock() {
		return proxy.getDatabasehash(true).orElse("");
	}

	@Override
	public void storePassphrase(String vault, String displayName, CharSequence password) throws KeychainAccessException {
		storePassphrase(vault, displayName, password, false);
	}

	@Override
	public void storePassphrase(String vault, String name, CharSequence password, boolean requireOsAuthentication) throws KeychainAccessException {
		if (isLocked()) {
			LOG.info("Failed to store password. KeePassXC database is locked. Needs to be unlocked first.");
			unlock();
			return;
		}
		ensureAssociation();
		var urlVault = URL_SCHEME + vault;
		var group = proxy.createNewGroup(APP_NAME); // Store passphrase in group APP_NAME
		var login = proxy.loginExists(urlVault, null, false, List.of(proxy.exportConnection()), password.toString());
		if (login.isFound() && null != login.getUuid() && !login.getUuid().isBlank()) {
			return;
		}
		if (!proxy.setLogin(urlVault, null, null, name, password.toString(), APP_NAME, group.get("uuid"), null)) {
			throw new KeychainAccessException("Storing of the password failed");
		} else {
			LOG.info("Password successfully stored for vault {}", urlVault.substring(URL_SCHEME.length()));
		}
	}

	@Override
	public char[] loadPassphrase(String vault) throws KeychainAccessException {
		if (isLocked()) {
			LOG.info("Failed to load password. KeePassXC database is locked. Needs to be unlocked first.");
			unlock();
			return null;
		}
		ensureAssociation();
		var urlVault = URL_SCHEME + vault;
		var answer = proxy.getLogins(urlVault, null, false, List.of(proxy.exportConnection()));
		if (answer.isEmpty() || null == answer.get("entries")) {
			LOG.info("No password found for vault {}", urlVault.substring(URL_SCHEME.length()));
			return null;
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
		if (isLocked()) {
			LOG.info("Failed to delete password. KeePassXC database is locked. Needs to be unlocked first.");
			unlock();
			return;
		}
		ensureAssociation();
		var urlVault = URL_SCHEME + vault;
		var answer = proxy.getLogins(urlVault, null, false, List.of(proxy.exportConnection()));
		if (answer.isEmpty() || null == answer.get("entries")) {
			LOG.info("No password stored for vault {}", urlVault.substring(URL_SCHEME.length()));
			return;
		}
		var array = (ArrayList<Object>) answer.get("entries");
		var credentials = (HashMap<String, Object>) array.get(0);
		if (credentials.get("uuid") != null) {
			var uuid = (String) credentials.get("uuid");
			LOG.info(proxy.deleteEntry(uuid) ? "Password for vault {} deleted"
					: "Deleting password for vault {} failed", urlVault.substring(URL_SCHEME.length()));
		} else {
			throw new KeychainAccessException("Couldn't retrieve uuid of the entry");
		}
	}

	@Override
	public void changePassphrase(String vault, CharSequence password) throws KeychainAccessException {
		changePassphrase(vault, "Vault", password);
	}

	@Override
	public void changePassphrase(String vault, String name, CharSequence password) throws KeychainAccessException {
		if (isLocked()) {
			LOG.info("Failed to change password. KeePassXC database is locked. Needs to be unlocked first.");
			unlock();
			return;
		}
		ensureAssociation();
		var urlVault = URL_SCHEME + vault;
		var group = proxy.createNewGroup(APP_NAME); // Update passphrase in group APP_NAME
		var answer = proxy.getLogins(urlVault, null, false, List.of(proxy.exportConnection()));
		if (answer.isEmpty() || null == answer.get("entries")) {
			LOG.info("No password found for vault {}", urlVault.substring(URL_SCHEME.length()));
			return;
		}
		var array = (ArrayList<Object>) answer.get("entries");
		var credentials = (HashMap<String, Object>) array.get(0);
		var uuid = (String) credentials.get("uuid");
		if (!proxy.setLogin(urlVault, null, null, name, password.toString(), APP_NAME, group.get("uuid"), uuid)) {
			throw new KeychainAccessException("Changing the password failed");
		}
	}
}
