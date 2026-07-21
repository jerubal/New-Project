package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.dto.CsrSignRequest;
import org.insa.pkiissuingca.dto.IntermediateCaInitRequest;
import org.insa.pkiissuingca.dto.RevokeRequest;
import org.insa.pkiissuingca.dto.RootCaInitRequest;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.service.CertificateLifecycleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/certificates")
public class CertificateController {

    @Autowired
    private CertificateLifecycleService lifecycleService;

    @Autowired
    private CertificateRepository certificateRepository;

    @PostMapping("/cas/root")
//    @PreAuthorize("hasRole('ROLE_CA_ADMIN')")
    public ResponseEntity<?> initRootCa(@RequestBody RootCaInitRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity rootCa = lifecycleService.initRootCa(
                    request.getSubjectDN(),
                    request.getKeyType(),
                    request.getKeySizeOrCurve(),
                    request.getProfileName() != null ? request.getProfileName() : "RootCA",
                    username
            );
            return ResponseEntity.ok(rootCa);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to initialize Root CA: " + e.getMessage());
        }
    }

    @PostMapping("/cas/intermediate")
//    @PreAuthorize("hasRole('ROLE_CA_ADMIN')")
    public ResponseEntity<?> initIntermediateCa(@RequestBody IntermediateCaInitRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity intermediateCa = lifecycleService.initIntermediateCa(
                    request.getSubjectDN(),
                    request.getParentSerialNumber(),
                    request.getKeyType(),
                    request.getKeySizeOrCurve(),
                    request.getProfileName() != null ? request.getProfileName() : "SubCA",
                    username
            );
            return ResponseEntity.ok(intermediateCa);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to initialize Intermediate CA: " + e.getMessage());
        }
    }

    @PostMapping("/sign")
//    @PreAuthorize("hasAnyRole('ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> signCsr(@RequestBody CsrSignRequest request) {
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
            return ResponseEntity.badRequest().body("Failed to sign CSR: " + e.getMessage());
        }
    }

    @PostMapping(value = {"/{serialNumber}/renew", "/{serialNumber}/renewed"})
//    @PreAuthorize("hasAnyRole('ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> renewCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity renewed = lifecycleService.renewCertificate(serialNumber, username);
            return ResponseEntity.ok(renewed);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to renew certificate: " + e.getMessage());
        }
    }

    @PostMapping(value = {"/{serialNumber}/suspend", "/{serialNumber}/suspended"})
//    @PreAuthorize("hasAnyRole('ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> suspendCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity suspended = lifecycleService.suspendCertificate(serialNumber, username);
            return ResponseEntity.ok(suspended);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to suspend certificate: " + e.getMessage());
        }
    }

    @PostMapping(value = {"/{serialNumber}/unsuspend", "/{serialNumber}/unsuspended"})
//    @PreAuthorize("hasAnyRole('ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> unsuspendCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity unsuspended = lifecycleService.unsuspendCertificate(serialNumber, username);
            return ResponseEntity.ok(unsuspended);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to unsuspend certificate: " + e.getMessage());
        }
    }

    @PostMapping(value = {"/{serialNumber}/revoke", "/{serialNumber}/revoked"})
//    @PreAuthorize("hasAnyRole('ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> revokeCertificate(@PathVariable String serialNumber, @RequestBody(required = false) RevokeRequest request) {
        String username = getCurrentUsername();
        String reason = (request != null) ? request.getReason() : "UNSPECIFIED";
        try {
            CertificateEntity revoked = lifecycleService.revokeCertificate(serialNumber, reason, username);
            return ResponseEntity.ok(revoked);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to revoke certificate: " + e.getMessage());
        }
    }

    @GetMapping
//    @PreAuthorize("hasAnyRole('ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_AUDITOR')")
    public ResponseEntity<List<CertificateEntity>> listCertificates() {
        return ResponseEntity.ok(certificateRepository.findAll());
    }

    @GetMapping("/{serialNumber}")
//    @PreAuthorize("hasAnyRole('ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_AUDITOR', 'ROLE_END_ENTITY')")
    public ResponseEntity<?> getCertificate(@PathVariable String serialNumber) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber).orElse(null);
        if (cert == null) {
            return ResponseEntity.notFound().build();
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

    private String getCurrentUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return "admin";
        }
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal == null) {
            return "admin";
        }
        if (principal instanceof String) {
            return (String) principal;
        }
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            return ((org.springframework.security.core.userdetails.UserDetails) principal).getUsername();
        }
        return principal.toString();
    }
}
