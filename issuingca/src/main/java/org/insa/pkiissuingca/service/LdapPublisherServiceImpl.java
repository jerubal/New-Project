package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Base64;

@Service
public class LdapPublisherServiceImpl implements LdapPublisherService {

    private static final Logger log = LoggerFactory.getLogger(LdapPublisherServiceImpl.class);

    @Autowired(required = false)
    private LdapTemplate ldapTemplate;

    @Autowired
    private AuditService auditService;

    @Value("${ldap.enabled:false}")
    private boolean ldapEnabled;

    @Value("${ldap.cert-attribute:cACertificate;binary}")
    private String certAttributeName;

    @Value("${ldap.crl-attribute:certificateRevocationList;binary}")
    private String crlAttributeName;

    @Value("${ldap.max-retries:3}")
    private int maxRetries;

    @Value("${ldap.retry-backoff-ms:1000}")
    private long retryBackoffMs;

    @Override
    @Async
    public void publishCertificate(CertificateEntity cert) {
        if (!ldapEnabled) {
            log.debug("LDAP publishing is disabled (ldap.enabled=false). Skipping certificate {}", cert.getSerialNumber());
            return;
        }
        if (ldapTemplate == null) {
            log.warn("LdapTemplate bean not configured. Skipping certificate publication {}", cert.getSerialNumber());
            return;
        }

        executeWithRetry("PublishCertificate", cert.getSubjectDN(), () -> {
            byte[] certDer = extractDerFromPem(cert.getPemContent());
            Attribute attr = new BasicAttribute(certAttributeName, certDer);
            ModificationItem item = new ModificationItem(DirContext.ADD_ATTRIBUTE, attr);

            String dn = mapSubjectDnToLdapDn(cert.getSubjectDN());
            try {
                ldapTemplate.modifyAttributes(dn, new ModificationItem[]{item});
            } catch (Exception e) {
                // If entry doesn't exist, try binding a new entry
                Attributes attrs = new BasicAttributes();
                Attribute oc = new BasicAttribute("objectClass");
                oc.add("top");
                oc.add("pkiCA");
                attrs.put(oc);
                attrs.put(attr);
                ldapTemplate.bind(dn, null, attrs);
            }
            log.info("Successfully published certificate serial {} to LDAP DN: {}", cert.getSerialNumber(), dn);
        });
    }

    @Override
    @Async
    public void publishCrl(CrlEntity crl) {
        if (!ldapEnabled) {
            log.debug("LDAP publishing is disabled (ldap.enabled=false). Skipping CRL #{}", crl.getCrlNumber());
            return;
        }
        if (ldapTemplate == null) {
            log.warn("LdapTemplate bean not configured. Skipping CRL publication #{}", crl.getCrlNumber());
            return;
        }

        String caSubjectDn = crl.getCaCertificate().getSubjectDN();
        executeWithRetry("PublishCRL", caSubjectDn, () -> {
            Attribute attr = new BasicAttribute(crlAttributeName, crl.getDerContent());
            ModificationItem item = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attr);

            String dn = mapSubjectDnToLdapDn(caSubjectDn);
            try {
                ldapTemplate.modifyAttributes(dn, new ModificationItem[]{item});
            } catch (Exception e) {
                Attributes attrs = new BasicAttributes();
                Attribute oc = new BasicAttribute("objectClass");
                oc.add("top");
                oc.add("pkiCA");
                attrs.put(oc);
                attrs.put(attr);
                ldapTemplate.bind(dn, null, attrs);
            }
            log.info("Successfully published CRL #{} for CA serial {} to LDAP DN: {}",
                    crl.getCrlNumber(), crl.getCaCertificate().getSerialNumber(), dn);
        });
    }

    private void executeWithRetry(String operationName, String targetDn, Runnable runnable) {
        int attempts = 0;
        Exception lastException = null;

        while (attempts < maxRetries) {
            attempts++;
            try {
                runnable.run();
                return; // Success
            } catch (Exception e) {
                lastException = e;
                log.warn("LDAP operation '{}' attempt {}/{} failed for target '{}': {}",
                        operationName, attempts, maxRetries, targetDn, e.getMessage());
                if (attempts < maxRetries) {
                    try {
                        Thread.sleep(retryBackoffMs * (long) Math.pow(2, attempts - 1));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }

        // Exhausted retries — log error to AuditLogEntity without throwing exception to caller
        log.error("LDAP operation '{}' failed after {} attempts for target '{}'", operationName, maxRetries, targetDn, lastException);
        auditService.log("SYSTEM", "LDAP_PUBLISH_FAILURE",
                "LDAP " + operationName + " failed for target DN: " + targetDn + ". Error: " +
                        (lastException != null ? lastException.getMessage() : "Unknown"), "FAILURE", "127.0.0.1");
    }

    private String mapSubjectDnToLdapDn(String subjectDn) {
        // Simple mapping keeping original X.500 DN relative components
        return subjectDn.trim();
    }

    private byte[] extractDerFromPem(String pem) {
        String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(base64);
    }
}
