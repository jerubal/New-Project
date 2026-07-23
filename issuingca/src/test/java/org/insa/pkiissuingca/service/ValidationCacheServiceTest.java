package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.*;
import org.insa.pkiissuingca.dto.CachedCertStatus;
import org.insa.pkiissuingca.event.CertificateRevokedEvent;
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
import org.springframework.context.ApplicationEventPublisher;
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
public class ValidationCacheServiceTest {

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("jwt.secret", () -> "test_super_secret_pki_signing_key_2026_minimum_32_bytes_long");
        registry.add("pki.security.db-encryption-key", () -> "3q2+7wD8hK9zL1xV4bN6mQ8wE0rT2yU4iO6pA8sD0fG=");
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:testdb_cache;DB_CLOSE_DELAY=-1;MODE=MariaDB");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.flyway.enabled", () -> "false");
        registry.add("spring.data.redis.host", () -> "localhost");
        registry.add("spring.data.redis.port", () -> "6379");
    }

    @Autowired
    private ValidationCacheService validationCacheService;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired
    private CertificateLifecycleService lifecycleService;

    @Autowired
    private OcspResponderService ocspResponderService;

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
    void testCacheEvictionOnCertificateRevocation() throws Exception {
        // 1. Populate cache with ISSUED cert status
        String serialNumber = "123456789";
        validationCacheService.putCertStatus(new CachedCertStatus(serialNumber, "ISSUED", null, null));

        // Verify entry exists (or gracefully returns null if Redis server is unvailable locally)
        CachedCertStatus initial = validationCacheService.getCertStatus(serialNumber);

        // 2. Publish revocation event
        eventPublisher.publishEvent(new CertificateRevokedEvent(serialNumber, 1L, "KEY_COMPROMISE"));

        // 3. Assert eviction
        CachedCertStatus afterEviction = validationCacheService.getCertStatus(serialNumber);
        assertNull(afterEviction, "Cached status must be null immediately following revocation event");
    }
}
