package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.insa.pkiissuingca.model.*;
import org.insa.pkiissuingca.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class OcspResponderServiceImpl implements OcspResponderService {

    private static final Logger log = LoggerFactory.getLogger(OcspResponderServiceImpl.class);

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private OcspSignerRepository ocspSignerRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HsmService hsmService;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private ValidationCacheService validationCacheService;

    @Value("${pki.ocsp.signer-validity-days:7}")
    private int ocspSignerValidityDays;

    @Value("${pki.ocsp.response-ttl-seconds:300}")
    private int responseTtlSeconds;

    @Override
    @Transactional
    public OcspSignerEntity issueOcspSignerCertificate(String caSerial, String username) throws Exception {
        CertificateEntity caCertEntity = certificateRepository.findBySerialNumber(caSerial)
                .orElseThrow(() -> new IllegalArgumentException("CA certificate not found for serial: " + caSerial));

        if (!"ISSUED".equalsIgnoreCase(caCertEntity.getStatus())) {
            throw new IllegalStateException("Parent CA certificate is not active. Status: " + caCertEntity.getStatus());
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        // Load CA Key pair & X509
        KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(caCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Parent CA private key not found."));

        PrivateKey caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());
        X509Certificate caX509 = serializationService.parseCertificateFromPem(caCertEntity.getPemContent());

        // Generate OCSP Signer KeyPair
        KeyPair signerKeyPair = cryptoService.generateRsaKeyPair(2048, true);
        KeyPairEntity signerKpEntity = new KeyPairEntity();
        signerKpEntity.setAlgorithm("RSA");
        signerKpEntity.setKeySize(2048);
        
        if (hsmService.isHsmEnabled()) {
            signerKpEntity.setPrivateKeyPEM("HSM:PENDING");
        } else {
            signerKpEntity.setPrivateKeyPEM(serializationService.convertToPem(signerKeyPair.getPrivate()));
        }
        
        signerKpEntity.setPublicKeyPEM(serializationService.convertToPem(signerKeyPair.getPublic()));
        signerKpEntity.setCreatedAt(Instant.now());
        signerKpEntity.setUser(user);
        signerKpEntity = keyPairRepository.save(signerKpEntity);

        // Build short-lived OCSP Signer Certificate
        Instant now = Instant.now();
        Instant notAfter = now.plus(Duration.ofDays(ocspSignerValidityDays));
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        String subjectDN = "CN=OCSP Responder (" + caSerial + "),O=INSA,C=FR";
        X500Name subject = new X500Name(subjectDN);
        X500Name issuer = new X500Name(caCertEntity.getSubjectDN());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, Date.from(now.minusSeconds(300)), Date.from(notAfter), subject, signerKeyPair.getPublic()
        );

        // Key Usage: Digital Signature
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        // Extended Key Usage: id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
        certBuilder.addExtension(Extension.extendedKeyUsage, true,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));

        // OCSPNoCheck Extension (1.3.6.1.5.5.7.48.1.5)
        certBuilder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE);

        ContentSigner signer = cryptoService.getContentSigner(caPrivateKey, "SHA256withRSA");
        X509Certificate signerCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        CertificateEntity signerCertEntity = new CertificateEntity();
        signerCertEntity.setSerialNumber(serial.toString());
        signerCertEntity.setSubjectDN(subjectDN);
        signerCertEntity.setIssuerDN(caCertEntity.getSubjectDN());
        signerCertEntity.setNotBefore(now.minusSeconds(300));
        signerCertEntity.setNotAfter(notAfter);
        signerCertEntity.setPublicKeyPEM(signerKpEntity.getPublicKeyPEM());
        signerCertEntity.setStatus("ISSUED");
        signerCertEntity.setPemContent(serializationService.convertToPem(signerCert));
        signerCertEntity.setCertificateType("OCSP_SIGNER");
        signerCertEntity.setProfileName("OCSP_SIGNER");
        signerCertEntity.setParentCa(caCertEntity);

        CertificateEntity savedCert = certificateRepository.save(signerCertEntity);

        if ("HSM:PENDING".equals(signerKpEntity.getPrivateKeyPEM())) {
            String alias = serial.toString();
            hsmService.storeInHsm(alias, signerKeyPair.getPrivate(), new java.security.cert.Certificate[]{signerCert});
            signerKpEntity.setPrivateKeyPEM("HSM:" + alias);
            keyPairRepository.save(signerKpEntity);
        }

        // Revoke older active signers for this CA
        List<OcspSignerEntity> existing = ocspSignerRepository.findByCaCertificateIdOrderByCreatedAtDesc(caCertEntity.getId());
        for (OcspSignerEntity oldSigner : existing) {
            if ("ACTIVE".equalsIgnoreCase(oldSigner.getStatus())) {
                oldSigner.setStatus("EXPIRED");
                ocspSignerRepository.save(oldSigner);
            }
        }

        // Save OcspSignerEntity
        OcspSignerEntity ocspSigner = new OcspSignerEntity();
        ocspSigner.setCaCertificate(caCertEntity);
        ocspSigner.setSignerCertificate(savedCert);
        ocspSigner.setKeyPair(signerKpEntity);
        ocspSigner.setStatus("ACTIVE");
        ocspSigner.setCreatedAt(now);
        ocspSigner.setExpiresAt(notAfter);

        OcspSignerEntity savedSigner = ocspSignerRepository.save(ocspSigner);

        auditService.log(username, "ISSUE_OCSP_SIGNER",
                "Issued OCSP Signer Cert Serial: " + serial + " for CA Serial: " + caSerial, "SUCCESS", "127.0.0.1");

        return savedSigner;
    }

    @Override
    public byte[] handleRequest(byte[] ocspRequestDer, String caSerial) throws Exception {
        OCSPReq ocspReq;
        try {
            ocspReq = new OCSPReq(ocspRequestDer);
        } catch (Exception e) {
            log.error("Invalid OCSP Request payload: {}", e.getMessage());
            return new OCSPRespBuilder().build(OCSPResponseStatus.MALFORMED_REQUEST, null).getEncoded();
        }

        CertificateEntity caCert = certificateRepository.findBySerialNumber(caSerial).orElse(null);
        if (caCert == null) {
            log.warn("OCSP request received for unknown CA Serial: {}", caSerial);
            return new OCSPRespBuilder().build(OCSPResponseStatus.UNAUTHORIZED, null).getEncoded();
        }

        // Get or automatically provision active OCSP Signer identity for this CA
        OcspSignerEntity activeSigner = ocspSignerRepository
                .findFirstByCaCertificateIdAndStatusOrderByCreatedAtDesc(caCert.getId(), "ACTIVE")
                .orElse(null);

        if (activeSigner == null || activeSigner.getExpiresAt().isBefore(Instant.now())) {
            log.info("No active OCSP Signer found for CA Serial: {}. Auto-issuing new signer.", caSerial);
            activeSigner = issueOcspSignerCertificate(caSerial, "SYSTEM");
        }

        PrivateKey signerPrivateKey = serializationService.parsePrivateKeyFromPem(activeSigner.getKeyPair().getPrivateKeyPEM());
        X509Certificate signerX509 = serializationService.parseCertificateFromPem(activeSigner.getSignerCertificate().getPemContent());
        X509CertificateHolder signerHolder = new JcaX509CertificateHolder(signerX509);

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        RespID respID = new RespID(signerHolder.getSubject());
        JcaBasicOCSPRespBuilder respBuilder = new JcaBasicOCSPRespBuilder(signerX509.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));

        Req[] requests = ocspReq.getRequestList();
        Instant now = Instant.now();
        Instant nextUpdate = now.plus(Duration.ofSeconds(responseTtlSeconds));

        for (Req req : requests) {
            CertificateID certId = req.getCertID();
            BigInteger queriedSerial = certId.getSerialNumber();
            String serialStr = queriedSerial.toString();

            // 1. Check Redis cache first
            org.insa.pkiissuingca.dto.CachedCertStatus cachedStatus = validationCacheService.getCertStatus(serialStr);
            String status;
            String revocationReason = null;
            Instant revocationTime = null;

            if (cachedStatus != null) {
                status = cachedStatus.getStatus();
                revocationReason = cachedStatus.getRevocationReason();
                revocationTime = cachedStatus.getRevocationDate();
            } else {
                // DB Fallback on cache miss
                Optional<CertificateEntity> targetCertOpt = certificateRepository.findBySerialNumber(serialStr);
                if (targetCertOpt.isEmpty()) {
                    respBuilder.addResponse(certId, new UnknownStatus());
                    continue;
                } else {
                    CertificateEntity targetCert = targetCertOpt.get();
                    status = targetCert.getStatus();
                    revocationReason = targetCert.getRevocationReason();
                    revocationTime = targetCert.getRevocationDate();

                    // Populate Redis cache
                    validationCacheService.putCertStatus(new org.insa.pkiissuingca.dto.CachedCertStatus(
                            serialStr, status, revocationReason, revocationTime
                    ));
                }
            }

            if ("ISSUED".equalsIgnoreCase(status)) {
                respBuilder.addResponse(certId, CertificateStatus.GOOD);
            } else if ("REVOKED".equalsIgnoreCase(status)) {
                Instant revTime = revocationTime != null ? revocationTime : now;
                int reasonCode = mapReasonCode(revocationReason);
                respBuilder.addResponse(certId, new RevokedStatus(Date.from(revTime), reasonCode));
            } else if ("SUSPENDED".equalsIgnoreCase(status)) {
                Instant revTime = revocationTime != null ? revocationTime : now;
                respBuilder.addResponse(certId, new RevokedStatus(Date.from(revTime), CRLReason.certificateHold));
            } else {
                respBuilder.addResponse(certId, new UnknownStatus());
            }
        }

        // Echo Nonce extension if requested (RFC 8954)
        Extension nonceExt = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonceExt != null) {
            respBuilder.setResponseExtensions(new Extensions(nonceExt));
        }

        ContentSigner contentSigner = cryptoService.getContentSigner(signerPrivateKey, "SHA256withRSA");
        X509CertificateHolder[] chain = new X509CertificateHolder[]{ signerHolder };

        BasicOCSPResp basicResp = respBuilder.build(contentSigner, chain, Date.from(now));
        OCSPResp ocspResp = new OCSPRespBuilder().build(OCSPResponseStatus.SUCCESSFUL, basicResp);

        return ocspResp.getEncoded();
    }

    @Scheduled(fixedRateString = "${pki.ocsp.signer-check-interval-ms:86400000}")
    public void autoRenewOcspSigners() {
        List<CertificateEntity> activeCas = certificateRepository.findByStatus("ISSUED");
        Instant now = Instant.now();
        Instant renewThreshold = now.plus(Duration.ofDays(2));

        for (CertificateEntity ca : activeCas) {
            if ("END_ENTITY".equalsIgnoreCase(ca.getCertificateType())) continue;

            Optional<OcspSignerEntity> activeSignerOpt = ocspSignerRepository
                    .findFirstByCaCertificateIdAndStatusOrderByCreatedAtDesc(ca.getId(), "ACTIVE");

            if (activeSignerOpt.isEmpty() || activeSignerOpt.get().getExpiresAt().isBefore(renewThreshold)) {
                try {
                    log.info("Auto-renewing OCSP Signer Certificate for CA Serial: {}", ca.getSerialNumber());
                    issueOcspSignerCertificate(ca.getSerialNumber(), "SYSTEM");
                } catch (Exception e) {
                    log.error("Failed to auto-renew OCSP Signer Certificate for CA Serial: {}", ca.getSerialNumber(), e);
                }
            }
        }
    }

    private int mapReasonCode(String reasonStr) {
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

    private String normalizePem(String pem) {
        if (pem == null) return "";
        return pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
    }
}
