package org.insa.pkiissuingca.controller;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.insa.pkiissuingca.dto.KeystoreConvertRequest;
import org.insa.pkiissuingca.dto.KeystoreExportRequest;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.insa.pkiissuingca.service.AuditService;
import org.insa.pkiissuingca.service.CryptoService;
import org.insa.pkiissuingca.service.KeystoreService;
import org.insa.pkiissuingca.service.SerializationService;
import org.insa.pkiissuingca.service.HsmService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class KeystoreControllerTest {

    private static final HsmService hsmService = org.mockito.Mockito.mock(HsmService.class);
    private static final CryptoService cryptoService = new CryptoService(hsmService);
    private static final SerializationService serializationService = new SerializationService();
    private static final KeystoreService keystoreService = new KeystoreService();

    static {
        ReflectionTestUtils.setField(serializationService, "hsmService", hsmService);
    }

    @BeforeAll
    public static void setUpBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testExportPkcs12Success() throws Exception {
        KeyPair keyPair = cryptoService.generateRsaKeyPair(2048);
        X509Certificate cert = generateCert(keyPair);
        String certPem = serializationService.convertToPem(cert);
        String privateKeyPem = serializationService.convertToPem(keyPair.getPrivate());

        CertificateEntity certEntity = new CertificateEntity();
        certEntity.setSerialNumber("123456789");
        certEntity.setPemContent(certPem);

        KeyPairEntity keyPairEntity = new KeyPairEntity();
        keyPairEntity.setId(1L);
        keyPairEntity.setPrivateKeyPEM(privateKeyPem);

        // Dummy AuditService stub
        AuditService dummyAuditService = new AuditService() {
            @Override
            public org.insa.pkiissuingca.model.AuditLogEntity log(String username, String action, String details, String status, String ipAddress) {
                return new org.insa.pkiissuingca.model.AuditLogEntity();
            }
        };

        KeystoreController controller = new KeystoreController();
        ReflectionTestUtils.setField(controller, "keystoreService", keystoreService);
        ReflectionTestUtils.setField(controller, "serializationService", serializationService);
        ReflectionTestUtils.setField(controller, "auditService", dummyAuditService);

        // Mock CertificateRepository using Proxy or Stub
        CertificateRepository mockCertRepo = org.mockito.Mockito.mock(CertificateRepository.class);
        KeyPairRepository mockKeyRepo = org.mockito.Mockito.mock(KeyPairRepository.class);
        org.mockito.Mockito.when(mockCertRepo.findBySerialNumber("123456789")).thenReturn(Optional.of(certEntity));
        org.mockito.Mockito.when(mockKeyRepo.findById(1L)).thenReturn(Optional.of(keyPairEntity));

        ReflectionTestUtils.setField(controller, "certificateRepository", mockCertRepo);
        ReflectionTestUtils.setField(controller, "keyPairRepository", mockKeyRepo);

        KeystoreExportRequest request = new KeystoreExportRequest();
        request.setSerialNumber("123456789");
        request.setKeyId(1L);
        request.setPassword("exportpass");
        request.setAlias("testalias");

        ResponseEntity<?> response = controller.exportPkcs12(request);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertTrue(response.getBody() instanceof byte[]);

        // Verify exported byte array is a valid PKCS12 store
        byte[] p12Bytes = (byte[]) response.getBody();
        KeyStore loadedStore = keystoreService.loadKeyStore(p12Bytes, "PKCS12", "exportpass");
        assertTrue(loadedStore.containsAlias("testalias"));
    }

    @Test
    public void testConvertKeystoreSuccess() throws Exception {
        KeyPair keyPair = cryptoService.generateRsaKeyPair(2048);
        X509Certificate cert = generateCert(keyPair);

        // Create valid source JKS
        KeyStore jksStore = keystoreService.createKeyStore("JKS");
        keystoreService.storePrivateKey(jksStore, "myalias", keyPair.getPrivate(), "jkspass", new java.security.cert.Certificate[]{cert});
        byte[] jksBytes = keystoreService.saveKeyStore(jksStore, "jkspass");

        AuditService dummyAuditService = new AuditService() {
            @Override
            public org.insa.pkiissuingca.model.AuditLogEntity log(String username, String action, String details, String status, String ipAddress) {
                return new org.insa.pkiissuingca.model.AuditLogEntity();
            }
        };

        KeystoreController controller = new KeystoreController();
        ReflectionTestUtils.setField(controller, "keystoreService", keystoreService);
        ReflectionTestUtils.setField(controller, "auditService", dummyAuditService);

        KeystoreConvertRequest request = new KeystoreConvertRequest();
        request.setSourceKeystoreBase64(Base64.getEncoder().encodeToString(jksBytes));
        request.setSourceType("JKS");
        request.setSourcePassword("jkspass");
        request.setTargetType("PKCS12");
        request.setTargetPassword("p12pass");

        ResponseEntity<?> response = controller.convertKeystore(request);
        assertEquals(200, response.getStatusCode().value());
        byte[] convertedBytes = (byte[]) response.getBody();
        assertNotNull(convertedBytes);

        // Verify converted PKCS12 keystore
        KeyStore convertedP12 = keystoreService.loadKeyStore(convertedBytes, "PKCS12", "p12pass");
        assertTrue(convertedP12.containsAlias("myalias"));
    }

    private X509Certificate generateCert(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        X500Name dn = new X500Name("CN=Test");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(now), new Date(now - 1000), new Date(now + 100000), dn, keyPair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }
}
