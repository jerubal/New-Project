package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.*;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.OcspSignerEntity;
import org.insa.pkiissuingca.model.Role;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.CertificateRepository;
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

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
public class OcspResponderServiceTest {

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("jwt.secret", () -> "test_super_secret_pki_signing_key_2026_minimum_32_bytes_long");
        registry.add("pki.security.db-encryption-key", () -> "3q2+7wD8hK9zL1xV4bN6mQ8wE0rT2yU4iO6pA8sD0fG=");
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:testdb_ocsp;DB_CLOSE_DELAY=-1;MODE=MariaDB");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.flyway.enabled", () -> "false");
    }

    @Autowired
    private CertificateLifecycleService lifecycleService;

    @Autowired
    private OcspResponderService ocspResponderService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private CsrService csrService;

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
    void testOcspRequestHandlingGoodAndRevoked() throws Exception {
        // 1. Initialize Root CA
        CertificateEntity rootCa = lifecycleService.initRootCa(
                "CN=OCSP Test Root CA,O=INSA,C=FR", "RSA", 2048, "RootCA", adminUser.getUsername());

        // 2. Issue End Entity Cert
        KeyPair eeKeyPair = cryptoService.generateRsaKeyPair(2048);
        String csrPem = csrService.generateCsr(eeKeyPair, "CN=ocsp.example.com,O=INSA,C=FR", null, "SHA256withRSA");
        CertificateEntity eeCert = lifecycleService.signCsr(csrPem, rootCa.getSerialNumber(), "EndEntity", adminUser.getUsername());

        // 3. Issue OCSP Signer Certificate
        OcspSignerEntity signerEntity = ocspResponderService.issueOcspSignerCertificate(rootCa.getSerialNumber(), adminUser.getUsername());
        assertNotNull(signerEntity);
        assertEquals("OCSP_SIGNER", signerEntity.getSignerCertificate().getCertificateType());

        // 4. Build OCSP Request for GOOD cert
        CertificateID certId = new CertificateID(
                new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1),
                new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(new SerializationService().parseCertificateFromPem(rootCa.getPemContent())),
                new BigInteger(eeCert.getSerialNumber())
        );

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certId);
        OCSPReq reqGood = reqBuilder.build();

        // 5. Handle GOOD OCSP Request
        byte[] respBytesGood = ocspResponderService.handleRequest(reqGood.getEncoded(), rootCa.getSerialNumber());
        OCSPResp ocspRespGood = new OCSPResp(respBytesGood);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspRespGood.getStatus());

        BasicOCSPResp basicRespGood = (BasicOCSPResp) ocspRespGood.getResponseObject();
        SingleResp singleRespGood = basicRespGood.getResponses()[0];
        assertNull(singleRespGood.getCertStatus()); // Null indicates GOOD status in BouncyCastle

        // 6. Revoke Cert & Test OCSP Status Change
        lifecycleService.revokeCertificate(eeCert.getSerialNumber(), "KEY_COMPROMISE", adminUser.getUsername());

        byte[] respBytesRev = ocspResponderService.handleRequest(reqGood.getEncoded(), rootCa.getSerialNumber());
        OCSPResp ocspRespRev = new OCSPResp(respBytesRev);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspRespRev.getStatus());

        BasicOCSPResp basicRespRev = (BasicOCSPResp) ocspRespRev.getResponseObject();
        SingleResp singleRespRev = basicRespRev.getResponses()[0];
        assertTrue(singleRespRev.getCertStatus() instanceof RevokedStatus);
    }
}
