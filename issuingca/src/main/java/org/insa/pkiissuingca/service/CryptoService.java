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
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
//cryptographic engine
@Service
public class CryptoService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates an RSA KeyPair of size 2048, 3072, or 4096 bits.
     */
    public KeyPair generateRsaKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (keySize != 2048 && keySize != 3072 && keySize != 4096) {
            throw new IllegalArgumentException("Unsupported RSA key size: " + keySize + ". Must be 2048, 3072, or 4096.");
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    /**
     * Generates an EC KeyPair for curve secp256r1, secp384r1, or secp521r1.
     */
    public KeyPair generateEcKeyPair(String curveName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        String standardName = resolveCurveName(curveName);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(new ECGenParameterSpec(standardName));
        return keyGen.generateKeyPair();
    }

    /**
     * Generates an Ed25519 (EdDSA) KeyPair.
     */
    public KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        return keyGen.generateKeyPair();
    }

    /**
     * Generates a PKCS#10 CSR in PEM format.
     */
    public String generateCsr(KeyPair keyPair, String subjectDn) throws Exception {
        // Use SHA256withRSA as default; adjust the algorithm string if you need support for EC/EdDSA signing
        String signatureAlgorithm = (keyPair.getPrivate().getAlgorithm().equals("RSA")) ? "SHA256withRSA" : "SHA256withECDSA";

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(subjectDn), keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

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