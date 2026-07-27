package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

//cryptographic engine
@Service
public class CryptoService {

    private final HsmService hsmService;

    @Autowired
    public CryptoService(HsmService hsmService) {
        this.hsmService = hsmService;
    }

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates an RSA KeyPair of size 2048, 3072, or 4096 bits.
     * Generates on HSM if useHsm is true.
     */
    public KeyPair generateRsaKeyPair(int keySize, boolean useHsm) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (keySize != 2048 && keySize != 3072 && keySize != 4096) {
            throw new IllegalArgumentException("Unsupported RSA key size: " + keySize + ". Must be 2048, 3072, or 4096.");
        }
        if (useHsm && hsmService.isHsmEnabled()) {
            return hsmService.generateRsaKeyPair(keySize);
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }
    
    public KeyPair generateRsaKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        return generateRsaKeyPair(keySize, false);
    }

    /**
     * Generates an EC KeyPair for curve secp256r1, secp384r1, or secp521r1.
     */
    public KeyPair generateEcKeyPair(String curveName, boolean useHsm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        String standardName = resolveCurveName(curveName);
        if (useHsm && hsmService.isHsmEnabled()) {
            return hsmService.generateEcKeyPair(standardName);
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(new ECGenParameterSpec(standardName));
        return keyGen.generateKeyPair();
    }
    
    public KeyPair generateEcKeyPair(String curveName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return generateEcKeyPair(curveName, false);
    }

    /**
     * Generates an Ed25519 (EdDSA) KeyPair.
     */
    public KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        return keyGen.generateKeyPair();
    }

    public PrivateKey getHsmPrivateKey(String alias) throws Exception {
        if (!hsmService.isHsmEnabled()) {
            throw new IllegalStateException("HSM is not enabled.");
        }
        // Need the PIN from somewhere. Actually, HsmService should handle this.
        // I will add a method to HsmService instead, and call it here.
        return hsmService.getPrivateKey(alias);
    }
    
    public ContentSigner getContentSigner(PrivateKey privateKey, String signatureAlgorithm) throws Exception {
        if (hsmService.isHsmEnabled()) {
             return hsmService.getHsmContentSigner(privateKey, signatureAlgorithm);
        } else {
             return new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);
        }
    }

    /**
     * Generates a PKCS#10 CSR in PEM format.
     */
    public String generateCsr(KeyPair keyPair, String subjectDn) throws Exception {
        // Use SHA256withRSA as default; adjust the algorithm string if you need support for EC/EdDSA signing
        String signatureAlgorithm = (keyPair.getPrivate().getAlgorithm().equals("RSA")) ? "SHA256withRSA" : "SHA256withECDSA";

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(subjectDn), keyPair.getPublic());

        ContentSigner signer = getContentSigner(keyPair.getPrivate(), signatureAlgorithm);

        PKCS10CertificationRequest csr = p10Builder.build(signer);

        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        }
        return sw.toString();
    }

    private String resolveCurveName(String curveName) {
        if (curveName.equalsIgnoreCase("P-256")) return "secp256r1";
        if (curveName.equalsIgnoreCase("P-384")) return "secp384r1";
        if (curveName.equalsIgnoreCase("P-521")) return "secp521r1";
        return curveName;
    }
}