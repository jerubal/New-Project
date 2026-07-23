package org.insa.pkiissuingca.controller;

import jakarta.validation.Valid;
import org.insa.pkiissuingca.dto.KeystoreConvertRequest;
import org.insa.pkiissuingca.dto.KeystoreExportRequest;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.insa.pkiissuingca.service.AuditService;
import org.insa.pkiissuingca.service.KeystoreService;
import org.insa.pkiissuingca.service.SerializationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/api/v1/keystores")
public class KeystoreController {

    private static final Logger log = LoggerFactory.getLogger(KeystoreController.class);

    @Autowired
    private KeystoreService keystoreService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private AuditService auditService;

    @PostMapping("/export-p12")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'END_ENTITY', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_END_ENTITY')")
    public ResponseEntity<?> exportPkcs12(@Valid @RequestBody KeystoreExportRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity certEntity = certificateRepository.findBySerialNumber(request.getSerialNumber())
                    .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + request.getSerialNumber()));

            KeyPairEntity keyPairEntity = keyPairRepository.findById(request.getKeyId())
                    .orElseThrow(() -> new IllegalArgumentException("KeyPair not found with ID: " + request.getKeyId()));

            if (!isUserAdminOrOperator()) {
                if (keyPairEntity.getUser() == null || keyPairEntity.getUser().getUsername() == null ||
                        !keyPairEntity.getUser().getUsername().equals(username)) {
                    auditService.log(username, "EXPORT_PFX_PKCS12", "Access denied for keyId " + request.getKeyId(), "FAILURE", "127.0.0.1");
                    return ResponseEntity.status(403).body("Access denied: You do not own this key pair.");
                }
            }

            PrivateKey privateKey = serializationService.parsePrivateKeyFromPem(keyPairEntity.getPrivateKeyPEM());
            X509Certificate targetCert = serializationService.parseCertificateFromPem(certEntity.getPemContent());

            // Build certificate chain (target cert + parent CAs)
            List<Certificate> chainList = new ArrayList<>();
            chainList.add(targetCert);
            CertificateEntity currentParent = certEntity.getParentCa();
            while (currentParent != null) {
                X509Certificate parentCert = serializationService.parseCertificateFromPem(currentParent.getPemContent());
                chainList.add(parentCert);
                currentParent = currentParent.getParentCa();
            }
            Certificate[] chain = chainList.toArray(new Certificate[0]);

            String alias = (request.getAlias() != null && !request.getAlias().isBlank()) ? request.getAlias() : "pki-entry";

            KeyStore pkcs12Store = keystoreService.createKeyStore("PKCS12");
            keystoreService.storePrivateKey(pkcs12Store, alias, privateKey, request.getPassword(), chain);
            byte[] p12Bytes = keystoreService.saveKeyStore(pkcs12Store, request.getPassword());

            auditService.log(username, "EXPORT_PFX_PKCS12",
                    "Exported PKCS12 for cert serial: " + request.getSerialNumber(), "SUCCESS", "127.0.0.1");

            String filename = "cert-" + request.getSerialNumber() + ".p12";
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .contentType(MediaType.parseMediaType("application/x-pkcs12"))
                    .body(p12Bytes);

        } catch (Exception e) {
            auditService.log(username, "EXPORT_PFX_PKCS12", "Export failed", "FAILURE", "127.0.0.1");
            log.error("Failed to export PKCS12 for cert {}: {}", request.getSerialNumber(), e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to export PKCS12/PFX.");
        }
    }

    @PostMapping("/convert")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> convertKeystore(@Valid @RequestBody KeystoreConvertRequest request) {
        String username = getCurrentUsername();
        try {
            byte[] sourceBytes = Base64.getDecoder().decode(request.getSourceKeystoreBase64());
            byte[] convertedBytes = keystoreService.convertKeystore(
                    sourceBytes,
                    request.getSourceType(),
                    request.getSourcePassword(),
                    request.getTargetType(),
                    request.getTargetPassword()
            );

            auditService.log(username, "CONVERT_KEYSTORE",
                    "Converted keystore from " + request.getSourceType() + " to " + request.getTargetType(),
                    "SUCCESS", "127.0.0.1");

            String ext = "PKCS12".equalsIgnoreCase(request.getTargetType()) ? "p12" : "jks";
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"converted-keystore." + ext + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(convertedBytes);

        } catch (Exception e) {
            auditService.log(username, "CONVERT_KEYSTORE", "Conversion failed", "FAILURE", "127.0.0.1");
            log.error("Failed to convert keystore: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to convert keystore.");
        }
    }

    private boolean isUserAdminOrOperator() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return false;
        return auth.getAuthorities().stream().anyMatch(a ->
                a.getAuthority().equals("ROLE_CA_ADMIN") || a.getAuthority().equals("CA_ADMIN") ||
                a.getAuthority().equals("ROLE_RA_OPERATOR") || a.getAuthority().equals("RA_OPERATOR")
        );
    }

    private String getCurrentUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return "SYSTEM";
        }
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal == null) {
            return "SYSTEM";
        }
        if (principal instanceof String) {
            String str = (String) principal;
            return "anonymousUser".equalsIgnoreCase(str) ? "SYSTEM" : str;
        }
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            return ((org.springframework.security.core.userdetails.UserDetails) principal).getUsername();
        }
        return principal.toString();
    }
}
