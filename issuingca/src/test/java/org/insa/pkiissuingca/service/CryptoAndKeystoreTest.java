package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoAndKeystoreTest {

    private final CryptoService cryptoService = new CryptoService();
    private final SerializationService serializationService = new SerializationService();
    private final KeystoreService keystoreService = new KeystoreService();

    @BeforeAll
    public static void setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDN, String sigAlg) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * 365);
        X500Name dnName = new X500Name(subjectDN);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName,
                BigInteger.valueOf(now),
                notBefore,
                notAfter,
                dnName,
                keyPair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }

    @Test
    public void testKeyGeneration() throws Exception {
        // Test RSA key sizes
        KeyPair rsa2048 = cryptoService.generateRsaKeyPair(2048);
        assertNotNull(rsa2048);
        assertEquals("RSA", rsa2048.getPublic().getAlgorithm());

        KeyPair rsa4096 = cryptoService.generateRsaKeyPair(4096);
        assertNotNull(rsa4096);

        // Test EC Curves
        KeyPair ec256 = cryptoService.generateEcKeyPair("secp256r1");
        assertNotNull(ec256);
        assertEquals("EC", ec256.getPublic().getAlgorithm());

        KeyPair ec384 = cryptoService.generateEcKeyPair("secp384r1");
        assertNotNull(ec384);

        // Test Ed25519
        KeyPair ed25519 = cryptoService.generateEd25519KeyPair();
        assertNotNull(ed25519);
        assertEquals("Ed25519", ed25519.getPublic().getAlgorithm());
    }

    @Test
    public void testSerializationAndParsing() throws Exception {
        KeyPair keyPair = cryptoService.generateRsaKeyPair(2048);
        
        // Serialize Private Key to PEM and parse back
        String privatePem = serializationService.convertToPem(keyPair.getPrivate());
        assertTrue(privatePem.contains("PRIVATE KEY"));
        PrivateKey parsedPrivate = serializationService.parsePrivateKeyFromPem(privatePem);
        assertArrayEquals(keyPair.getPrivate().getEncoded(), parsedPrivate.getEncoded());

        // Serialize Public Key to PEM and parse back
        String publicPem = serializationService.convertToPem(keyPair.getPublic());
        assertTrue(publicPem.contains("PUBLIC KEY"));
        PublicKey parsedPublic = serializationService.parsePublicKeyFromPem(publicPem);
        assertArrayEquals(keyPair.getPublic().getEncoded(), parsedPublic.getEncoded());

        // Generate self-signed certificate, serialize to PEM & DER and parse back
        X509Certificate certificate = generateSelfSignedCertificate(keyPair, "CN=Test Authority", "SHA256withRSA");
        String certPem = serializationService.convertToPem(certificate);
        assertTrue(certPem.contains("CERTIFICATE"));
        X509Certificate parsedCertFromPem = serializationService.parseCertificateFromPem(certPem);
        assertEquals(certificate.getSerialNumber(), parsedCertFromPem.getSerialNumber());

        byte[] certDer = serializationService.convertToDer(certificate);
        X509Certificate parsedCertFromDer = serializationService.parseCertificateFromDer(certDer);
        assertEquals(certificate.getSerialNumber(), parsedCertFromDer.getSerialNumber());
    }

    @Test
    public void testKeystoreOperationsAndConversion() throws Exception {
        KeyPair keyPair = cryptoService.generateRsaKeyPair(2048);
        X509Certificate cert = generateSelfSignedCertificate(keyPair, "CN=Root CA", "SHA256withRSA");
        Certificate[] chain = new Certificate[]{cert};

        // Create empty PKCS12 Keystore
        KeyStore p12Store = keystoreService.createKeyStore("PKCS12");
        keystoreService.storePrivateKey(p12Store, "rootca", keyPair.getPrivate(), "keystorepass", chain);

        // Save PKCS12 Keystore to bytes
        byte[] p12Bytes = keystoreService.saveKeyStore(p12Store, "keystorepass");
        assertNotNull(p12Bytes);

        // Load PKCS12 Keystore from bytes
        KeyStore loadedStore = keystoreService.loadKeyStore(p12Bytes, "PKCS12", "keystorepass");
        assertTrue(loadedStore.containsAlias("rootca"));

        PrivateKey extractedKey = keystoreService.extractPrivateKey(loadedStore, "rootca", "keystorepass");
        assertArrayEquals(keyPair.getPrivate().getEncoded(), extractedKey.getEncoded());

        Certificate[] extractedChain = keystoreService.extractCertificateChain(loadedStore, "rootca");
        assertEquals(1, extractedChain.length);
        assertEquals(cert.getSerialNumber(), ((X509Certificate) extractedChain[0]).getSerialNumber());

        // Convert Keystore PKCS12 to JKS
        byte[] jksBytes = keystoreService.convertKeystore(p12Bytes, "PKCS12", "keystorepass", "JKS", "jks-password");
        assertNotNull(jksBytes);

        // Load JKS and verify
        KeyStore loadedJks = keystoreService.loadKeyStore(jksBytes, "JKS", "jks-password");
        assertTrue(loadedJks.containsAlias("rootca"));
    }

    @Test
    public void testCsrGenerationAndParsing() throws Exception {
        CsrService csrService = new CsrService();
        ReflectionTestUtils.setField(csrService, "serializationService", serializationService);

        KeyPair keyPair = cryptoService.generateRsaKeyPair(2048);
        String subjectDN = "CN=Client Application,O=INSA,C=FR";
        
        // Generate CSR
        String csrPem = csrService.generateCsr(keyPair, subjectDN, Collections.singletonList("DNS:example.com"), "SHA256withRSA");
        assertTrue(csrPem.contains("CERTIFICATE REQUEST"));

        // Parse & Validate CSR signature (Proof-of-Possession)
        CsrService.CsrDetails details = csrService.parseCsr(csrPem);
        assertTrue(details.getSubjectDN().contains("CN=Client Application"));
        assertTrue(details.getSubjectDN().contains("O=INSA"));
        assertArrayEquals(keyPair.getPublic().getEncoded(), details.getPublicKey().getEncoded());
        assertEquals(1, details.getSans().size());
        assertTrue(details.getSans().get(0).contains("example.com"));
    }

    @Test
    public void testCsrPolicyValidationWeakAlgorithm() throws Exception {
        CsrService csrService = new CsrService();
        ReflectionTestUtils.setField(csrService, "serializationService", serializationService);

        KeyPair keyPair = cryptoService.generateRsaKeyPair(2048);
        String subjectDN = "CN=WeakAlgTest,O=INSA,C=FR";

        // Generate CSR with prohibited SHA1withRSA algorithm
        String weakCsrPem = csrService.generateCsr(keyPair, subjectDN, null, "SHA1withRSA");

        // Expect policy validation exception
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            csrService.parseCsr(weakCsrPem);
        });
        assertTrue(ex.getMessage().contains("Disallowed CSR signature algorithm"));
    }
}

