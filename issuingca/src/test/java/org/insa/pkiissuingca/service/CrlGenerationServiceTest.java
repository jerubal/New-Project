package org.insa.pkiissuingca.service;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.openssl.PEMParser;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.model.Role;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.CrlRepository;
import org.insa.pkiissuingca.repository.RoleRepository;
import org.insa.pkiissuingca.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

import java.io.StringReader;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
public class CrlGenerationServiceTest {

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("jwt.secret", () -> "test_super_secret_pki_signing_key_2026_minimum_32_bytes_long");
        registry.add("pki.security.db-encryption-key", () -> "3q2+7wD8hK9zL1xV4bN6mQ8wE0rT2yU4iO6pA8sD0fG=");
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;MODE=MariaDB");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.flyway.enabled", () -> "false");
    }

    @Autowired
    private CertificateLifecycleService lifecycleService;

    @Autowired
    private CrlGenerationService crlGenerationService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CrlRepository crlRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User adminUser;

    @BeforeEach
    void setUp() {
        Role role = roleRepository.findByName("ROLE_CA_ADMIN").orElseGet(() -> {
            Role r = new Role();
            r.setName("ROLE_CA_ADMIN");
            return roleRepository.save(r);
        });

        adminUser = userRepository.findByUsername("admin").orElseGet(() -> {
            User u = new User();
            u.setUsername("admin");
            u.setPassword(passwordEncoder.encode("password"));
            u.setEmail("admin@test.org");
            u.setEnabled(true);
            u.setRoles(new HashSet<>(Collections.singletonList(role)));
            return userRepository.save(u);
        });
    }

    @Test
    void testCrlGenerationAndEventDrivenUpdate() throws Exception {
        // 1. Initialize Root CA
        CertificateEntity rootCa = lifecycleService.initRootCa(
                "CN=Test Root CA,O=INSA,C=FR", "RSA", 2048, "RootCA", adminUser.getUsername());
        assertNotNull(rootCa);

        // 2. Initialize Intermediate CA
        CertificateEntity subCa = lifecycleService.initIntermediateCa(
                "CN=Test Sub CA,O=INSA,C=FR", rootCa.getSerialNumber(), "RSA", 2048, "SubCA", adminUser.getUsername());
        assertNotNull(subCa);

        // 3. Generate CSR & Sign End Entity Certificate
        String csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIICvDCCAaQCAQAwFDESMBAGA1UEAwwKZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQC1aJ5T5i+H+X8L2Q5N/W9C0W3tU4+G1K0J8Z8V\n" +
                "x5nL1w9zK9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9\n" +
                "Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z\n" +
                "8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8\n" +
                "V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2AgMBAAGgADANBgkqhkiG\n" +
                "9w0BAQsFAAOCAQEAA0b1d3X3y5Z5y8+Z9v1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2\n" +
                "b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b\n" +
                "3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3\n" +
                "+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9Xn2b3+\n" +
                "Q9u2n9Z8V1w2+X9Xn2b3+Q9u2n9Z8V1w2+X9g==\n" +
                "-----END CERTIFICATE REQUEST-----";

        // Generate a real CSR using CryptoService & CsrService to avoid parsing errors
        java.security.KeyPair kp = new org.insa.pkiissuingca.service.CryptoService().generateRsaKeyPair(2048);
        String realCsrPem = new org.insa.pkiissuingca.service.CsrService().generateCsr(kp, "CN=test.example.com,O=INSA,C=FR", null, "SHA256withRSA");

        CertificateEntity eeCert = lifecycleService.signCsr(realCsrPem, subCa.getSerialNumber(), "EndEntity", adminUser.getUsername());
        assertNotNull(eeCert);

        // 4. Generate Initial CRL for Sub CA (should have 0 revoked entries)
        CrlEntity crl1 = crlGenerationService.generateCrl(subCa.getId());
        assertNotNull(crl1);
        assertEquals(1L, crl1.getCrlNumber());
        assertEquals(0, crl1.getRevokedCount());

        // Parse PEM CRL to verify format
        try (PEMParser parser = new PEMParser(new StringReader(crl1.getPemContent()))) {
            Object parsed = parser.readObject();
            assertTrue(parsed instanceof X509CRLHolder);
        }

        // 5. Revoke Certificate — should trigger event-driven CRL generation (CRL #2)
        lifecycleService.revokeCertificate(eeCert.getSerialNumber(), "KEY_COMPROMISE", adminUser.getUsername());

        Optional<CrlEntity> latestCrlOpt = crlGenerationService.getLatestCrlByCaSerial(subCa.getSerialNumber());
        assertTrue(latestCrlOpt.isPresent());
        CrlEntity crl2 = latestCrlOpt.get();

        assertEquals(2L, crl2.getCrlNumber());
        assertEquals(1, crl2.getRevokedCount());
    }
}
