package org.purejava.integrations.keychain;

import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.cryptomator.integrations.keychain.KeychainAccessProvider;
import org.purejava.KeepassProxyAccess;
import org.purejava.KeepassProxyAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class KeePassXCAccess implements KeychainAccessProvider {

	private static final Logger LOG = LoggerFactory.getLogger(KeePassXCAccess.class);
	private KeepassProxyAccess proxy;

	KeePassXCAccess() {
		this.proxy = new KeepassProxyAccess();
		try {
			this.proxy.connect();
			this.proxy.associate();
		} catch (IOException | KeepassProxyAccessException e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean isSupported() { return true; }

	@Override
	public boolean isLocked() {
		return false;
	}

	@Override
	public void storePassphrase(String s, CharSequence charSequence) throws KeychainAccessException {

	}

	@Override
	public char[] loadPassphrase(String s) throws KeychainAccessException {
		return new char[0];
	}

	@Override
	public void deletePassphrase(String s) throws KeychainAccessException {

	}

	@Override
	public void changePassphrase(String s, CharSequence charSequence) throws KeychainAccessException {

	}
}
