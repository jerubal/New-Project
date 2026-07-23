package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@SpringBootTest
public class LdapPublisherServiceTest {

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("jwt.secret", () -> "test_super_secret_pki_signing_key_2026_minimum_32_bytes_long");
        registry.add("pki.security.db-encryption-key", () -> "3q2+7wD8hK9zL1xV4bN6mQ8wE0rT2yU4iO6pA8sD0fG=");
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:testdb_ldap;DB_CLOSE_DELAY=-1;MODE=MariaDB");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.flyway.enabled", () -> "false");
        registry.add("ldap.enabled", () -> "true");
        registry.add("ldap.url", () -> "ldap://localhost:10389");
    }

    @Autowired
    private LdapPublisherService ldapPublisherService;

    @Test
    void testLdapPublishGracefulFailureWhenServerUnreachable() {
        CertificateEntity cert = new CertificateEntity();
        cert.setSerialNumber("99999");
        cert.setSubjectDN("CN=Unreachable Test,O=INSA,C=FR");
        cert.setPemContent("-----BEGIN CERTIFICATE-----\nMIIC...==\n-----END CERTIFICATE-----");

        CrlEntity crl = new CrlEntity();
        crl.setCrlNumber(1L);
        crl.setCaCertificate(cert);
        crl.setDerContent(new byte[]{0x30, 0x00});

        // Assert that executing LDAP publish against unreachable server retries and logs without throwing exception
        assertDoesNotThrow(() -> {
            ldapPublisherService.publishCertificate(cert);
            ldapPublisherService.publishCrl(crl);
        });
    }
}
