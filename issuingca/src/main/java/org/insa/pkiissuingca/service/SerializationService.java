package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Service
public class SerializationService {

    /**
     * Converts any supported object (Certificate, KeyPair, CSR, PrivateKey) into standard PEM format.
     */
    public String convertToPem(Object obj) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(obj);
        }
        return sw.toString();
    }

    /**
     * Parses an X.509 Certificate from a PEM string.
     */
    /**
     * Parses an X.509 Certificate from a PEM string, sanitizing the input
     * to ignore extra data or trailing characters.
     */
    public X509Certificate parseCertificateFromPem(String pemContent) throws Exception {
        // Use regex to find the first valid certificate block
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                java.util.regex.Pattern.DOTALL
        );
        java.util.regex.Matcher matcher = pattern.matcher(pemContent);

        if (!matcher.find()) {
            throw new IOException("No valid PEM-encoded certificate found in stream");
        }

        String cleanPem = matcher.group(0);

        try (PEMParser parser = new PEMParser(new StringReader(cleanPem))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate((X509CertificateHolder) obj);
            }
            throw new IOException("No valid certificate found in the sanitized PEM block");
        }
    }

    /**
     * Parses a Private Key from a PEM string.
     */
    public PrivateKey parsePrivateKeyFromPem(String pemStr) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemStr))) {
            Object parsed = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (parsed instanceof PEMKeyPair) {
                return converter.getPrivateKey(((PEMKeyPair) parsed).getPrivateKeyInfo());
            } else if (parsed instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) parsed);
            } else if (parsed instanceof PrivateKey) {
                return (PrivateKey) parsed;
            }
            throw new IllegalArgumentException("Provided PEM does not contain a valid Private Key.");
        }
    }

    /**
     * Parses a Public Key from a PEM string.
     */
    public PublicKey parsePublicKeyFromPem(String pemStr) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemStr))) {
            Object parsed = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (parsed instanceof SubjectPublicKeyInfo) {
                return converter.getPublicKey((SubjectPublicKeyInfo) parsed);
            } else if (parsed instanceof PublicKey) {
                return (PublicKey) parsed;
            }
            throw new IllegalArgumentException("Provided PEM does not contain a valid Public Key.");
        }
    }

    /**
     * Serializes an X.509 Certificate into binary DER format.
     */
    public byte[] convertToDer(X509Certificate cert) throws Exception {
        return cert.getEncoded();
    }

    /**
     * Deserializes an X.509 Certificate from binary DER format.
     */
    public X509Certificate parseCertificateFromDer(byte[] derBytes) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(derBytes));
    }

    /**
     * Serializes a Private Key into binary DER format.
     */
    public byte[] convertToDer(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }
    public java.security.KeyPair convertToKeyPair(String privateKeyPem, String publicKeyPem) throws Exception {
        java.security.PrivateKey privateKey = parsePrivateKeyFromPem(privateKeyPem);
        java.security.PublicKey publicKey = parsePublicKeyFromPem(publicKeyPem);
        return new java.security.KeyPair(publicKey, privateKey);
    }

    /**
     * Deserializes a Private Key from binary DER format.
     */
    public PrivateKey parsePrivateKeyFromDer(byte[] derBytes, String algorithm) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(derBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, "BC");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Serializes a Public Key into binary DER format.
     */
    public byte[] convertToDer(PublicKey publicKey) {
        return publicKey.getEncoded();
    }

    /**
     * Deserializes a Public Key from binary DER format.
     */
    public PublicKey parsePublicKeyFromDer(byte[] derBytes, String algorithm) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, "BC");
        return keyFactory.generatePublic(keySpec);
    }
}
