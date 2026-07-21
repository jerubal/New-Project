package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CertificateProfileEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.CertificateProfileRepository;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.insa.pkiissuingca.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class CertificateLifecycleService {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private CertificateProfileRepository profileRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private CsrService csrService;

    @Autowired
    private AuditService auditService;

    /**
     * Instantiates a self-signed Root CA.
     */
    @Transactional
    public CertificateEntity initRootCa(String subjectDN, String keyType, int keySizeOrCurve, String profileName, String username) throws Exception {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        // Generate Root CA KeyPair
        KeyPair keyPair;
        String algorithm;
        if ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) {
            String curve = keySizeOrCurve == 384 ? "secp384r1" : (keySizeOrCurve == 521 ? "secp521r1" : "secp256r1");
            keyPair = cryptoService.generateEcKeyPair(curve);
            algorithm = "EC";
        } else if ("Ed25519".equalsIgnoreCase(keyType)) {
            keyPair = cryptoService.generateEd25519KeyPair();
            algorithm = "Ed25519";
        } else {
            keyPair = cryptoService.generateRsaKeyPair(keySizeOrCurve > 0 ? keySizeOrCurve : 2048);
            algorithm = "RSA";
        }

        // Save KeyPair
        KeyPairEntity kpEntity = new KeyPairEntity();
        kpEntity.setAlgorithm(algorithm);
        kpEntity.setKeySize(keySizeOrCurve);
        kpEntity.setPrivateKeyPEM(serializationService.convertToPem(keyPair.getPrivate()));
        kpEntity.setPublicKeyPEM(serializationService.convertToPem(keyPair.getPublic()));
        kpEntity.setCreatedAt(Instant.now());
        kpEntity.setUser(user);
        kpEntity = keyPairRepository.save(kpEntity);

        // Fetch or create profile
        CertificateProfileEntity profile = profileRepository.findByName(profileName)
                .orElseGet(() -> createDefaultProfile(profileName, true, 3650, "SHA256withRSA"));

        // Build self-signed cert
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5); // 5 mins ago
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(subjectDN);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );

        // Extensions
        // Basic Constraints
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        // Key Usage
        int keyUsageFlags = KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature;
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageFlags));

        // Subject Key Identifier
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(keyPair.getPublic().getEncoded()));

        String sigAlg = profile.getSignatureAlgorithm();
        if ("EC".equals(algorithm)) {
            sigAlg = "SHA256withECDSA";
        } else if ("Ed25519".equals(algorithm)) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        CertificateEntity certEntity = new CertificateEntity();
        certEntity.setSerialNumber(serial.toString());
        certEntity.setSubjectDN(subjectDN);
        certEntity.setIssuerDN(subjectDN);
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(kpEntity.getPublicKeyPEM());
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType("ROOT");
        certEntity.setProfileName(profileName);

        CertificateEntity saved = certificateRepository.save(certEntity);

        auditService.log(username, "INIT_ROOT_CA", "Initialized Root CA with DN: " + subjectDN + ", Serial: " + serial, "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Provision an Intermediate CA signed by a Root CA or another parent CA.
     */
    @Transactional
    public CertificateEntity initIntermediateCa(String subjectDN, String parentSerialNumber, String keyType, int keySizeOrCurve, String profileName, String username) throws Exception {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        CertificateEntity parentCertEntity = certificateRepository.findBySerialNumber(parentSerialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Parent CA certificate not found for serial: " + parentSerialNumber));

        if (!"ISSUED".equals(parentCertEntity.getStatus())) {
            throw new IllegalStateException("Parent CA certificate is not active. Status: " + parentCertEntity.getStatus());
        }

        // Generate Intermediate CA KeyPair
        KeyPair keyPair;
        String algorithm;
        if ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) {
            String curve = keySizeOrCurve == 384 ? "secp384r1" : (keySizeOrCurve == 521 ? "secp521r1" : "secp256r1");
            keyPair = cryptoService.generateEcKeyPair(curve);
            algorithm = "EC";
        } else if ("Ed25519".equalsIgnoreCase(keyType)) {
            keyPair = cryptoService.generateEd25519KeyPair();
            algorithm = "Ed25519";
        } else {
            keyPair = cryptoService.generateRsaKeyPair(keySizeOrCurve > 0 ? keySizeOrCurve : 2048);
            algorithm = "RSA";
        }

        // Save KeyPair
        KeyPairEntity kpEntity = new KeyPairEntity();
        kpEntity.setAlgorithm(algorithm);
        kpEntity.setKeySize(keySizeOrCurve);
        kpEntity.setPrivateKeyPEM(serializationService.convertToPem(keyPair.getPrivate()));
        kpEntity.setPublicKeyPEM(serializationService.convertToPem(keyPair.getPublic()));
        kpEntity.setCreatedAt(Instant.now());
        kpEntity.setUser(user);
        kpEntity = keyPairRepository.save(kpEntity);

        // Fetch parent CA Private Key
        KeyPairEntity parentKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(parentCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Parent CA private key not found in storage."));

        PrivateKey parentPrivateKey = serializationService.parsePrivateKeyFromPem(parentKeyPair.getPrivateKeyPEM());

        // Fetch or create profile
        CertificateProfileEntity profile = profileRepository.findByName(profileName)
                .orElseGet(() -> createDefaultProfile(profileName, true, 1825, "SHA256withRSA"));

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(subjectDN);
        X500Name issuer = new X500Name(parentCertEntity.getSubjectDN());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );

        // Extensions
        // Basic Constraints
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0)); // pathLen=0

        // Key Usage
        int keyUsageFlags = KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature;
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageFlags));

        // Subject Key Identifier
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(keyPair.getPublic().getEncoded()));

        // Authority Key Identifier
        X509Certificate parentX509 = serializationService.parseCertificateFromPem(parentCertEntity.getPemContent());
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(parentX509.getPublicKey().getEncoded()));

        String sigAlg = profile.getSignatureAlgorithm();
        if (parentKeyPair.getAlgorithm().equalsIgnoreCase("EC")) {
            sigAlg = "SHA256withECDSA";
        } else if (parentKeyPair.getAlgorithm().equalsIgnoreCase("Ed25519")) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(parentPrivateKey);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        CertificateEntity certEntity = new CertificateEntity();
        certEntity.setSerialNumber(serial.toString());
        certEntity.setSubjectDN(subjectDN);
        certEntity.setIssuerDN(parentCertEntity.getSubjectDN());
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(kpEntity.getPublicKeyPEM());
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType("INTERMEDIATE");
        certEntity.setProfileName(profileName);

        CertificateEntity saved = certificateRepository.save(certEntity);

        auditService.log(username, "INIT_INTERMEDIATE_CA", "Initialized Intermediate CA: " + subjectDN + " signed by: " + parentCertEntity.getSubjectDN(), "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Signs an incoming CSR using a specified Sub-CA/Intermediate CA key.
     */
    @Transactional
    public CertificateEntity signCsr(String csrPem, String caSerialNumber, String profileName, String username) throws Exception {
        CertificateEntity caCertEntity = certificateRepository.findBySerialNumber(caSerialNumber)
                .orElseThrow(() -> new IllegalArgumentException("CA certificate not found for serial: " + caSerialNumber));

        if (!"ISSUED".equals(caCertEntity.getStatus())) {
            throw new IllegalStateException("CA is not active. Status: " + caCertEntity.getStatus());
        }

        CsrService.CsrDetails csrDetails = csrService.parseCsr(csrPem);

        // Fetch CA Key pair
        KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(caCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("CA Private Key not found."));

        PrivateKey caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());

        // Fetch or create profile
        CertificateProfileEntity profile = profileRepository.findByName(profileName)
                .orElseGet(() -> createDefaultProfile(profileName, false, 365, "SHA256withRSA"));

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(csrDetails.getSubjectDN());
        X500Name issuer = new X500Name(caCertEntity.getSubjectDN());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, csrDetails.getPublicKey()
        );

        // Extensions
        // Basic Constraints
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(profile.isBasicConstraints()));

        // Key Usage
        int keyUsageVal = 0;
        if (profile.getKeyUsage() != null) {
            String[] kuStrings = profile.getKeyUsage().split(",");
            for (String ku : kuStrings) {
                switch (ku.trim().toLowerCase()) {
                    case "digitalsignature": keyUsageVal |= KeyUsage.digitalSignature; break;
                    case "nonrepudiation": keyUsageVal |= KeyUsage.nonRepudiation; break;
                    case "keyencipherment": keyUsageVal |= KeyUsage.keyEncipherment; break;
                    case "dataencipherment": keyUsageVal |= KeyUsage.dataEncipherment; break;
                    case "keyagreement": keyUsageVal |= KeyUsage.keyAgreement; break;
                    case "keycertsign": keyUsageVal |= KeyUsage.keyCertSign; break;
                    case "crlsign": keyUsageVal |= KeyUsage.cRLSign; break;
                }
            }
        } else {
            keyUsageVal = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
        }
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageVal));

        // Extended Key Usage (EKU)
        if (profile.getExtendedKeyUsage() != null) {
            List<KeyPurposeId> purposeIds = new ArrayList<>();
            String[] ekuStrings = profile.getExtendedKeyUsage().split(",");
            for (String eku : ekuStrings) {
                switch (eku.trim().toLowerCase()) {
                    case "serverauth": purposeIds.add(KeyPurposeId.id_kp_serverAuth); break;
                    case "clientauth": purposeIds.add(KeyPurposeId.id_kp_clientAuth); break;
                    case "codesigning": purposeIds.add(KeyPurposeId.id_kp_codeSigning); break;
                    case "emailprotection": purposeIds.add(KeyPurposeId.id_kp_emailProtection); break;
                }
            }
            if (!purposeIds.isEmpty()) {
                certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposeIds.toArray(new KeyPurposeId[0])));
            }
        }

        // Subject Alternative Name (SAN)
        if (csrDetails.getSans() != null && !csrDetails.getSans().isEmpty()) {
            List<GeneralName> generalNamesList = new ArrayList<>();
            for (String san : csrDetails.getSans()) {
                // gn format could be tag:value (e.g. 2:example.com or 7:192.168.1.1)
                if (san.contains(":")) {
                    String[] parts = san.split(":", 2);
                    try {
                        int tag = Integer.parseInt(parts[0]);
                        generalNamesList.add(new GeneralName(tag, parts[1]));
                    } catch (NumberFormatException e) {
                        generalNamesList.add(new GeneralName(GeneralName.dNSName, san));
                    }
                } else {
                    generalNamesList.add(new GeneralName(GeneralName.dNSName, san));
                }
            }
            GeneralNames generalNames = new GeneralNames(generalNamesList.toArray(new GeneralName[0]));
            certBuilder.addExtension(Extension.subjectAlternativeName, false, generalNames);
        }

        // Subject Key Identifier
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(csrDetails.getPublicKey().getEncoded()));

        // Authority Key Identifier
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(caCertEntity.getPublicKeyPEM().getBytes()));

        String sigAlg = profile.getSignatureAlgorithm();
        if (caKeyPair.getAlgorithm().equalsIgnoreCase("EC")) {
            sigAlg = "SHA256withECDSA";
        } else if (caKeyPair.getAlgorithm().equalsIgnoreCase("Ed25519")) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caPrivateKey);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        CertificateEntity certEntity = new CertificateEntity();
        certEntity.setSerialNumber(serial.toString());
        certEntity.setSubjectDN(csrDetails.getSubjectDN());
        certEntity.setIssuerDN(caCertEntity.getSubjectDN());
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(serializationService.convertToPem(csrDetails.getPublicKey()));
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType("END_ENTITY");
        certEntity.setProfileName(profileName);

        CertificateEntity saved = certificateRepository.save(certEntity);

        auditService.log(username, "SIGN_CSR", "Signed CSR for Subject: " + csrDetails.getSubjectDN() + ", Serial: " + serial, "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Renews a certificate: generates a new certificate with extended validity using the same key.
     */
    @Transactional
    public CertificateEntity renewCertificate(String serialNumber, String username) throws Exception {
        CertificateEntity oldCert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

        if (!"ISSUED".equals(oldCert.getStatus())) {
            throw new IllegalStateException("Only ISSUED certificates can be renewed. Status: " + oldCert.getStatus());
        }

        CertificateProfileEntity profile = profileRepository.findByName(oldCert.getProfileName())
                .orElseGet(() -> createDefaultProfile(oldCert.getProfileName(), false, 365, "SHA256withRSA"));

        // FIX: Sanitize the PEM string to ensure it has correct headers and line breaks
        String rawPem = oldCert.getPemContent();
        String sanitizedPem = sanitizePem(rawPem);

        X509Certificate oldX509 = serializationService.parseCertificateFromPem(sanitizedPem);
        PublicKey pubKey = oldX509.getPublicKey();

        // Fetch Issuer CA
        CertificateEntity caCertEntity = certificateRepository.findBySubjectDN(oldCert.getIssuerDN()).stream()
                .filter(c -> "ROOT".equals(c.getCertificateType()) || "INTERMEDIATE".equals(c.getCertificateType()))
                .filter(c -> "ISSUED".equals(c.getStatus()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Issuer CA certificate not found or not active."));

        KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(caCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("CA Private Key not found."));

        PrivateKey caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(oldCert.getSubjectDN());
        X500Name issuer = new X500Name(caCertEntity.getSubjectDN());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, pubKey
        );

        // Copy extensions from old cert
        for (Extension ext : getExtensionsFromX509(oldX509)) {
            certBuilder.addExtension(ext);
        }

        String sigAlg = profile.getSignatureAlgorithm();
        if (caKeyPair.getAlgorithm().equalsIgnoreCase("EC")) {
            sigAlg = "SHA256withECDSA";
        } else if (caKeyPair.getAlgorithm().equalsIgnoreCase("Ed25519")) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caPrivateKey);
        X509Certificate newX509 = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        // Revoke the old certificate as "superceded"
        oldCert.setStatus("REVOKED");
        oldCert.setRevocationReason("SUPERSEDED");
        oldCert.setRevocationDate(Instant.now());
        certificateRepository.save(oldCert);

        // Save new certificate
        CertificateEntity newCert = new CertificateEntity();
        newCert.setSerialNumber(serial.toString());
        newCert.setSubjectDN(oldCert.getSubjectDN());
        newCert.setIssuerDN(oldCert.getIssuerDN());
        newCert.setNotBefore(notBefore.toInstant());
        newCert.setNotAfter(notAfter.toInstant());
        newCert.setPublicKeyPEM(oldCert.getPublicKeyPEM());
        newCert.setStatus("ISSUED");
        newCert.setPemContent(serializationService.convertToPem(newX509));
        newCert.setCertificateType(oldCert.getCertificateType());
        newCert.setProfileName(oldCert.getProfileName());

        CertificateEntity saved = certificateRepository.save(newCert);

        auditService.log(username, "RENEW_CERTIFICATE", "Renewed certificate. Old Serial: " + serialNumber + ", New Serial: " + serial, "SUCCESS", "127.0.0.1");

        return saved;
    }
    private String forceValidPemFormat(String pem) {
        if (pem == null) return "";

        // 1. Remove all existing line breaks and headers
        String base64Content = pem.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", ""); // Remove all whitespace/newlines

        // 2. Reconstruct with standard 64-character line breaks
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < base64Content.length(); i += 64) {
            int end = Math.min(i + 64, base64Content.length());
            sb.append(base64Content.substring(i, end)).append("\n");
        }
        sb.append("-----END CERTIFICATE-----");

        return sb.toString();
    }


    public String formatToPem(byte[] derEncodedCert) {
        String base64 = Base64.getEncoder().encodeToString(derEncodedCert);
        // Add line breaks every 64 chars to comply with PEM standards
        String formattedBase64 = base64.replaceAll("(.{64})", "$1\n");
        return "-----BEGIN CERTIFICATE-----\n" + formattedBase64 + "\n-----END CERTIFICATE-----";
    }
    // Helper to ensure PEM structure is valid for the parser
    private String sanitizePem(String pem) {
        if (pem == null) return "";

        String s = pem.trim();

        // Locate the start and end indices of the actual certificate block
        int start = s.indexOf("-----BEGIN CERTIFICATE-----");
        int end = s.indexOf("-----END CERTIFICATE-----");

        if (start != -1 && end != -1 && end > start) {
            // Extract ONLY the clean block
            return s.substring(start, end + "-----END CERTIFICATE-----".length());
        }

        // Fallback if formatting is completely broken (or handle as error)
        return s;
    }
    /**
     * Suspends a certificate (temporary suspension).
     */
    @Transactional
    public CertificateEntity suspendCertificate(String serialNumber, String username) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

        // DEBUG: Inspect the object state before any modifications
        System.out.println("--- DEBUG: Inspecting CertificateEntity ---");
        System.out.println("Serial: " + cert.getSerialNumber());
        System.out.println("CertificateType value: " + cert.getCertificateType()); // Check this output
        System.out.println("Status: " + cert.getStatus());
        System.out.println("-------------------------------------------");

        if (!"ISSUED".equals(cert.getStatus())) {
            throw new IllegalStateException("Only ISSUED certificates can be suspended. Current status: " + cert.getStatus());
        }

        cert.setStatus("SUSPENDED");
        CertificateEntity saved = certificateRepository.save(cert);

        auditService.log(username, "SUSPEND_CERTIFICATE", "Suspended certificate with Serial: " + serialNumber, "SUCCESS", "127.0.0.1");

        return saved;
    }
    /**
     * Unsuspends/activates a suspended certificate.
     */
    @Transactional
    public CertificateEntity unsuspendCertificate(String serialNumber, String username) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

        if (!"SUSPENDED".equals(cert.getStatus())) {
            throw new IllegalStateException("Only SUSPENDED certificates can be unsuspended. Current status: " + cert.getStatus());
        }

        cert.setStatus("ISSUED");
        CertificateEntity saved = certificateRepository.save(cert);

        auditService.log(username, "UNSUSPEND_CERTIFICATE", "Unsuspended certificate with Serial: " + serialNumber, "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Revokes a certificate permanently with a reason.
     */
    @Transactional
    public CertificateEntity revokeCertificate(String serialNumber, String reason, String username) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

        if ("REVOKED".equals(cert.getStatus())) {
            throw new IllegalStateException("Certificate is already revoked.");
        }

        cert.setStatus("REVOKED");
        cert.setRevocationReason(reason != null ? reason : "UNSPECIFIED");
        cert.setRevocationDate(Instant.now());
        CertificateEntity saved = certificateRepository.save(cert);

        auditService.log(username, "REVOKE_CERTIFICATE", "Revoked certificate with Serial: " + serialNumber + ", Reason: " + reason, "SUCCESS", "127.0.0.1");

        return saved;
    }

    private CertificateProfileEntity createDefaultProfile(String name, boolean isCa, int validityDays, String sigAlg) {
        CertificateProfileEntity profile = new CertificateProfileEntity();
        profile.setName(name);
        profile.setDescription("Default auto-created profile for " + name);
        profile.setBasicConstraints(isCa);
        profile.setValidityDays(validityDays);
        profile.setSignatureAlgorithm(sigAlg);
        if (isCa) {
            profile.setKeyUsage("digitalSignature,keyCertSign,cRLSign");
            profile.setPathLenConstraint(1);
        } else {
            profile.setKeyUsage("digitalSignature,keyEncipherment");
            profile.setExtendedKeyUsage("clientAuth,serverAuth");
        }
        return profileRepository.save(profile);
    }

    private List<Extension> getExtensionsFromX509(X509Certificate cert) throws Exception {
        List<Extension> list = new ArrayList<>();
        // BC extension parsing
        byte[] extOctets = cert.getExtensionValue(Extension.basicConstraints.getId());
        if (extOctets != null) {
            list.add(new Extension(Extension.basicConstraints, true, extOctets));
        }
        extOctets = cert.getExtensionValue(Extension.keyUsage.getId());
        if (extOctets != null) {
            list.add(new Extension(Extension.keyUsage, true, extOctets));
        }
        extOctets = cert.getExtensionValue(Extension.extendedKeyUsage.getId());
        if (extOctets != null) {
            list.add(new Extension(Extension.extendedKeyUsage, false, extOctets));
        }
        extOctets = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
        if (extOctets != null) {
            list.add(new Extension(Extension.subjectAlternativeName, false, extOctets));
        }
        return list;
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
