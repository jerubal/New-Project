package org.insa.pkiissuingca.service;

import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

@Service
public class KeystoreService {

    /**
     * Programmatically creates a new, empty KeyStore of the specified type (e.g., "PKCS12" or "JKS").
     */
    public KeyStore createKeyStore(String type) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);
        return keyStore;
    }

    /**
     * Programmatically loads an existing KeyStore from a byte array.
     */
    public KeyStore loadKeyStore(byte[] data, String type, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data)) {
            keyStore.load(bais, password != null ? password.toCharArray() : null);
        }
        return keyStore;
    }

    /**
     * Saves/serializes a KeyStore to a byte array.
     */
    public byte[] saveKeyStore(KeyStore keyStore, String password) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            keyStore.store(baos, password != null ? password.toCharArray() : null);
            return baos.toByteArray();
        }
    }

    /**
     * Stores a private key and its associated certificate chain in the keystore.
     */
    public void storePrivateKey(KeyStore keyStore, String alias, PrivateKey privateKey, String password, Certificate[] chain) throws Exception {
        keyStore.setKeyEntry(alias, privateKey, password != null ? password.toCharArray() : null, chain);
    }

    /**
     * Extracts a private key from the keystore.
     */
    public PrivateKey extractPrivateKey(KeyStore keyStore, String alias, String password) throws Exception {
        return (PrivateKey) keyStore.getKey(alias, password != null ? password.toCharArray() : null);
    }

    /**
     * Extracts the certificate chain associated with an alias.
     */
    public Certificate[] extractCertificateChain(KeyStore keyStore, String alias) throws Exception {
        return keyStore.getCertificateChain(alias);
    }

    /**
     * Converts a keystore from a source type (e.g. JKS) to a target type (e.g. PKCS12/PFX).
     */
    public byte[] convertKeystore(byte[] data, String sourceType, String sourcePassword, String targetType, String targetPassword) throws Exception {
        KeyStore srcStore = loadKeyStore(data, sourceType, sourcePassword);
        KeyStore targetStore = createKeyStore(targetType);

        Enumeration<String> aliases = srcStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (srcStore.isKeyEntry(alias)) {
                PrivateKey key = (PrivateKey) srcStore.getKey(alias, sourcePassword != null ? sourcePassword.toCharArray() : null);
                Certificate[] chain = srcStore.getCertificateChain(alias);
                targetStore.setKeyEntry(alias, key, targetPassword != null ? targetPassword.toCharArray() : null, chain);
            } else if (srcStore.isCertificateEntry(alias)) {
                Certificate cert = srcStore.getCertificate(alias);
                targetStore.setCertificateEntry(alias, cert);
            }
        }
        return saveKeyStore(targetStore, targetPassword);
    }
}
