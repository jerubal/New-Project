package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.insa.pkiissuingca.event.CertificateRevokedEvent;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.CrlRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
public class CrlGenerationServiceImpl implements CrlGenerationService {

    private static final Logger log = LoggerFactory.getLogger(CrlGenerationServiceImpl.class);

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private CrlRepository crlRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private LdapPublisherService ldapPublisherService;

    @Value("${pki.crl.validity-hours:24}")
    private int crlValidityHours;

    @Value("${pki.crl.expiration-buffer-hours:1}")
    private int expirationBufferHours;

    @Override
    @Transactional
    public CrlEntity generateCrl(Long caCertificateId) throws Exception {
        // Pessimistic write lock: held for the rest of this transaction, so a second concurrent
        // generateCrl() call for the same CA blocks here until this transaction commits, instead
        // of both transactions reading the same nextCrlNumber and racing to insert it.
        CertificateEntity caCertEntity = certificateRepository.findByIdForUpdate(caCertificateId)
                .orElseThrow(() -> new IllegalArgumentException("CA certificate not found with ID: " + caCertificateId));

        if (!"ISSUED".equalsIgnoreCase(caCertEntity.getStatus())) {
            throw new IllegalStateException("Cannot generate CRL for inactive CA. Status: " + caCertEntity.getStatus());
        }

        if ("END_ENTITY".equalsIgnoreCase(caCertEntity.getCertificateType())) {
            throw new IllegalArgumentException("Certificate ID " + caCertificateId + " is an End-Entity certificate, not a CA.");
        }

        // 1. CRL number allocation — safe now because the row lock above prevents any other
        // transaction from reading nextCrlNumber until this one commits or rolls back.
        Long currentCrlNumber = caCertEntity.getNextCrlNumber();
        caCertEntity.setNextCrlNumber(currentCrlNumber + 1);
        certificateRepository.save(caCertEntity);

        // 2. Load CA keys
        KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(caCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("CA Private Key not found for CA ID: " + caCertificateId));

        PrivateKey caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());
        X509Certificate caX509 = serializationService.parseCertificateFromPem(caCertEntity.getPemContent());

        // 3. Build CRL generator
        Instant now = Instant.now();
        Instant nextUpdate = now.plus(Duration.ofHours(crlValidityHours));

        X500Name issuerName = new X500Name(caCertEntity.getSubjectDN());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, Date.from(now));
        crlBuilder.setNextUpdate(Date.from(nextUpdate));

        // 4. Query revoked and suspended certificates issued by this CA
        List<CertificateEntity> revokedCerts = certificateRepository.findByParentCaIdAndStatusIn(
                caCertificateId, Arrays.asList("REVOKED", "SUSPENDED"));

        for (CertificateEntity cert : revokedCerts) {
            BigInteger serialNumber = new BigInteger(cert.getSerialNumber());
            Instant revocationTime = cert.getRevocationDate() != null ? cert.getRevocationDate() : now;
            int reasonCode = mapReasonCode(cert.getStatus(), cert.getRevocationReason());

            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(reasonCode));

            crlBuilder.addCRLEntry(serialNumber, Date.from(revocationTime), extGen.generate());
        }

        // 5. Extensions
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caX509));
        crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(currentCrlNumber));

        // 6. Sign CRL
        String sigAlg = getSignatureAlgorithm(caKeyPair.getAlgorithm(), caCertEntity.getProfileName());
        ContentSigner signer = cryptoService.getContentSigner(caPrivateKey, sigAlg);
        X509CRLHolder crlHolder = crlBuilder.build(signer);

        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
        X509CRL x509Crl = converter.getCRL(crlHolder);

        byte[] derBytes = x509Crl.getEncoded();
        String pemContent = serializationService.convertToPem(x509Crl);

        // 7. Persist CrlEntity
        CrlEntity crlEntity = new CrlEntity();
        crlEntity.setCaCertificate(caCertEntity);
        crlEntity.setCrlNumber(currentCrlNumber);
        crlEntity.setThisUpdate(now);
        crlEntity.setNextUpdate(nextUpdate);
        crlEntity.setDerContent(derBytes);
        crlEntity.setPemContent(pemContent);
        crlEntity.setRevokedCount(revokedCerts.size());
        crlEntity.setCreatedAt(now);

        CrlEntity saved = crlRepository.save(crlEntity);

        ldapPublisherService.publishCrl(saved);

        auditService.log("SYSTEM", "GENERATE_CRL",
                "Generated CRL #" + currentCrlNumber + " for CA: " + caCertEntity.getSerialNumber() +
                        ", Revoked Entries: " + revokedCerts.size(), "SUCCESS", "127.0.0.1");

        return saved;
    }

    @Override
    public Optional<CrlEntity> getLatestCrlByCaSerial(String caSerialNumber) {
        return certificateRepository.findBySerialNumber(caSerialNumber)
                .flatMap(ca -> crlRepository.findFirstByCaCertificateIdOrderByThisUpdateDesc(ca.getId()));
    }

    @Override
    public List<CrlEntity> getCrlHistoryByCaSerial(String caSerialNumber) {
        return certificateRepository.findBySerialNumber(caSerialNumber)
                .map(ca -> crlRepository.findByCaCertificateIdOrderByThisUpdateDesc(ca.getId()))
                .orElse(Collections.emptyList());
    }

    @EventListener
    public void handleCertificateRevoked(CertificateRevokedEvent event) {
        if (event.getParentCaId() == null) return;
        try {
            log.info("Event-driven CRL regeneration triggered for CA ID: {}", event.getParentCaId());
            generateCrl(event.getParentCaId());
        } catch (Exception e) {
            log.error("Event-driven CRL regeneration failed for CA ID: {}", event.getParentCaId(), e);
        }
    }

    @Scheduled(fixedRateString = "${pki.crl.regeneration-check-interval-ms:300000}")
    public void scheduledCrlRegenerationCheck() {
        List<CertificateEntity> activeCas = certificateRepository.findByStatus("ISSUED");
        Instant now = Instant.now();
        Instant bufferThreshold = now.plus(Duration.ofHours(expirationBufferHours));

        for (CertificateEntity ca : activeCas) {
            if ("END_ENTITY".equalsIgnoreCase(ca.getCertificateType())) continue;

            Optional<CrlEntity> latestCrl = crlRepository.findFirstByCaCertificateIdOrderByThisUpdateDesc(ca.getId());
            boolean needsRegeneration = latestCrl.isEmpty() || latestCrl.get().getNextUpdate().isBefore(bufferThreshold);

            if (needsRegeneration) {
                try {
                    log.info("Scheduled CRL regeneration for CA ID: {}, Serial: {}", ca.getId(), ca.getSerialNumber());
                    generateCrl(ca.getId());
                } catch (Exception e) {
                    log.error("Scheduled CRL regeneration failed for CA ID: {}", ca.getId(), e);
                }
            }
        }
    }

    private int mapReasonCode(String status, String reasonStr) {
        if ("SUSPENDED".equalsIgnoreCase(status)) {
            return CRLReason.certificateHold;
        }
        if (reasonStr == null) return CRLReason.unspecified;
        switch (reasonStr.toUpperCase()) {
            case "KEY_COMPROMISE": return CRLReason.keyCompromise;
            case "CA_COMPROMISE": return CRLReason.cACompromise;
            case "AFFILIATION_CHANGED": return CRLReason.affiliationChanged;
            case "SUPERSEDED": return CRLReason.superseded;
            case "CESSATION_OF_OPERATION": return CRLReason.cessationOfOperation;
            case "CERTIFICATE_HOLD": return CRLReason.certificateHold;
            default: return CRLReason.unspecified;
        }
    }

    private String getSignatureAlgorithm(String keyAlg, String profileName) {
        if ("EC".equalsIgnoreCase(keyAlg)) return "SHA256withECDSA";
        if ("Ed25519".equalsIgnoreCase(keyAlg)) return "Ed25519";
        return "SHA256withRSA";
    }

    private String normalizePem(String pem) {
        if (pem == null) return "";
        return pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
    }
}
