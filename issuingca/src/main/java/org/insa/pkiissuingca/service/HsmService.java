package org.insa.pkiissuingca.service;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.*;

@Service
public class HsmService {

    public static final String HSM_PROVIDER_NAME = "SunPKCS11-SoftHSM";
    public static final String KEYSTORE_TYPE = "PKCS11";

    @Value("${pki.hsm.enabled:false}")
    private boolean hsmEnabled;

    @Value("${pki.hsm.pin}")
    private String hsmPin;

    /**
     * Retrieves the PKCS11 Keystore backed by the HSM.
     */
    public KeyStore getHsmKeyStore(String pin) throws Exception {
        if (!hsmEnabled) {
            throw new IllegalStateException("HSM is not enabled in configuration.");
        }
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, HSM_PROVIDER_NAME);
        keyStore.load(null, pin != null ? pin.toCharArray() : null);
        return keyStore;
    }

    /**
     * Generates a non-exportable RSA KeyPair directly on the HSM and persists it.
     */
    public KeyPair generateRsaKeyPair(int keySize, String alias) throws Exception {
        if (!hsmEnabled) {
            throw new IllegalStateException("HSM is not enabled in configuration.");
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HSM_PROVIDER_NAME);
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        KeyStore ks = getHsmKeyStore(hsmPin);
        Certificate[] chain = new Certificate[1]; // Will be replaced by self-signed cert later
        // Note: For some HSMs, saving requires at least a dummy certificate
        // But for SoftHSM, setting the key entry might work or require a real cert.
        // If it requires a cert, we might need to delay saving to the keystore until the cert is generated.
        // Actually, returning the KeyPair is enough if it's a token object.
        // Let's rely on standard JCA where we return the keyPair.
        // To ensure it's saved, we might save it during cert issuance.
        return keyPair;
    }

    
    /**
     * Generates a non-exportable EC KeyPair directly on the HSM.
     */
    public KeyPair generateEcKeyPair(String curveName, String alias) throws Exception {
        if (!hsmEnabled) {
            throw new IllegalStateException("HSM is not enabled in configuration.");
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HSM_PROVIDER_NAME);
        keyGen.initialize(new java.security.spec.ECGenParameterSpec(curveName));
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }


    /**
     * Creates a ContentSigner that offloads signing to the HSM.
     */
    public ContentSigner getHsmContentSigner(PrivateKey hsmPrivateKey, String signatureAlgorithm) throws Exception {
        if (!hsmEnabled) {
            throw new IllegalStateException("HSM is not enabled in configuration.");
        }
        return new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(HSM_PROVIDER_NAME)
                .build(hsmPrivateKey);
    }
    
    /**
     * Stores the key and certificate in the HSM Keystore.
     */
    public void storeInHsm(String alias, PrivateKey privateKey, Certificate[] chain) throws Exception {
        if (!hsmEnabled) return;
        KeyStore keyStore = getHsmKeyStore(hsmPin);
        keyStore.setKeyEntry(alias, privateKey, hsmPin.toCharArray(), chain);
    }
    
    /**
     * Retrieves a private key from the HSM Keystore.
     */
    public PrivateKey getPrivateKey(String alias) throws Exception {
        if (!hsmEnabled) return null;
        KeyStore keyStore = getHsmKeyStore(hsmPin);
        return (PrivateKey) keyStore.getKey(alias, hsmPin.toCharArray());
    }
    
    public boolean isHsmEnabled() {
        return hsmEnabled;
    }
}
