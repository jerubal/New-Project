package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.dto.CsrSignRequest;
import org.insa.pkiissuingca.dto.IntermediateCaInitRequest;
import org.insa.pkiissuingca.dto.RevokeRequest;
import org.insa.pkiissuingca.dto.RootCaInitRequest;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.service.CertificateLifecycleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import jakarta.validation.Valid;

import org.springframework.context.annotation.Profile;

@RestController
@RequestMapping("/api/v1/certificates")
@Profile("!ocsp")
public class CertificateController {

    private static final Logger log = LoggerFactory.getLogger(CertificateController.class);

    @Autowired
    private CertificateLifecycleService lifecycleService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private org.insa.pkiissuingca.repository.KeyPairRepository keyPairRepository;

    @PostMapping("/cas/root")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN')")
    public ResponseEntity<?> initRootCa(@Valid @RequestBody RootCaInitRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity rootCa = lifecycleService.initRootCa(
                    request.getSubjectDN(),
                    request.getKeyType(),
                    request.getKeySizeOrCurve(),
                    request.getProfileName() != null ? request.getProfileName() : "RootCA",
                    request.getPathLenConstraint(),
                    username
            );
            return ResponseEntity.ok(rootCa);
        } catch (Exception e) {
            log.error("Failed to initialize Root CA: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to initialize Root CA.");
        }
    }

    @PostMapping("/cas/intermediate")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN')")
    public ResponseEntity<?> initIntermediateCa(@Valid @RequestBody IntermediateCaInitRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity intermediateCa = lifecycleService.initIntermediateCa(
                    request.getSubjectDN(),
                    request.getParentSerialNumber(),
                    request.getKeyType(),
                    request.getKeySizeOrCurve(),
                    request.getProfileName() != null ? request.getProfileName() : "SubCA",
                    request.getPathLenConstraint(),
                    username
            );
            return ResponseEntity.ok(intermediateCa);
        } catch (Exception e) {
            log.error("Failed to initialize Intermediate CA: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to initialize Intermediate CA.");
        }
    }

    @PostMapping("/sign")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> signCsr(@Valid @RequestBody CsrSignRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity cert = lifecycleService.signCsr(
                    request.getCsrPem(),
                    request.getCaSerialNumber(),
                    request.getProfileName() != null ? request.getProfileName() : "EndEntity",
                    username
            );
            return ResponseEntity.ok(cert);
        } catch (Exception e) {
            log.error("Failed to sign CSR: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to sign CSR.");
        }
    }

    @PostMapping(value = {"/{serialNumber}/renew", "/{serialNumber}/renewed"})
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> renewCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity renewed = lifecycleService.renewCertificate(serialNumber, username);
            return ResponseEntity.ok(renewed);
        } catch (Exception e) {
            log.error("Failed to renew certificate {}: {}", serialNumber, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to renew certificate.");
        }
    }

    @PostMapping(value = {"/{serialNumber}/suspend", "/{serialNumber}/suspended"})
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> suspendCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity suspended = lifecycleService.suspendCertificate(serialNumber, username);
            return ResponseEntity.ok(suspended);
        } catch (Exception e) {
            log.error("Failed to suspend certificate {}: {}", serialNumber, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to suspend certificate.");
        }
    }

    @PostMapping(value = {"/{serialNumber}/unsuspend", "/{serialNumber}/unsuspended"})
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> unsuspendCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity unsuspended = lifecycleService.unsuspendCertificate(serialNumber, username);
            return ResponseEntity.ok(unsuspended);
        } catch (Exception e) {
            log.error("Failed to unsuspend certificate {}: {}", serialNumber, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to unsuspend certificate.");
        }
    }

    @PostMapping(value = {"/{serialNumber}/revoke", "/{serialNumber}/revoked"})
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> revokeCertificate(@PathVariable String serialNumber, @RequestBody(required = false) RevokeRequest request) {
        String username = getCurrentUsername();
        String reason = (request != null) ? request.getReason() : "UNSPECIFIED";
        try {
            CertificateEntity revoked = lifecycleService.revokeCertificate(serialNumber, reason, username);
            return ResponseEntity.ok(revoked);
        } catch (Exception e) {
            log.error("Failed to revoke certificate {}: {}", serialNumber, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to revoke certificate.");
        }
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'AUDITOR', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_AUDITOR')")
    public ResponseEntity<List<CertificateEntity>> listCertificates() {
        return ResponseEntity.ok(certificateRepository.findAll());
    }

    @GetMapping("/tree")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'AUDITOR', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_AUDITOR')")
    public ResponseEntity<List<CertificateEntity>> getCertificateTree() {
        return ResponseEntity.ok(certificateRepository.findByParentCaIsNull());
    }

    @GetMapping("/{serialNumber}")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'RA_OPERATOR', 'AUDITOR', 'END_ENTITY', 'ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_AUDITOR', 'ROLE_END_ENTITY')")
    public ResponseEntity<?> getCertificate(@PathVariable String serialNumber) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber).orElse(null);
        if (cert == null) {
            return ResponseEntity.notFound().build();
        }

        // Ownership check for END_ENTITY users
        org.springframework.security.core.Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isEndEntityOnly = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_END_ENTITY") || a.getAuthority().equals("END_ENTITY"))
                && auth.getAuthorities().stream()
                .noneMatch(a -> a.getAuthority().equals("ROLE_CA_ADMIN") || a.getAuthority().equals("CA_ADMIN")
                             || a.getAuthority().equals("ROLE_RA_OPERATOR") || a.getAuthority().equals("RA_OPERATOR")
                             || a.getAuthority().equals("ROLE_AUDITOR") || a.getAuthority().equals("AUDITOR"));

        if (isEndEntityOnly) {
            String username = getCurrentUsername();
            if (!isUserOwnerOfCertificate(cert, username)) {
                return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN)
                        .body("Access Denied: You do not own this certificate.");
            }
        }

        return ResponseEntity.ok(cert);
    }

    @GetMapping("/{serialNumber}/pem")
    public ResponseEntity<String> getCertificatePem(@PathVariable String serialNumber) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber).orElse(null);
        if (cert == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(cert.getPemContent());
    }


    private boolean isUserOwnerOfCertificate(CertificateEntity cert, String username) {
        String certPubKey = normalizePem(cert.getPublicKeyPEM());
        return keyPairRepository.findAll().stream()
                .filter(kp -> kp.getUser() != null && kp.getUser().getUsername().equals(username))
                .anyMatch(kp -> normalizePem(kp.getPublicKeyPEM()).equals(certPubKey));
    }

    private String normalizePem(String pem) {
        if (pem == null) return "";
        return pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
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
