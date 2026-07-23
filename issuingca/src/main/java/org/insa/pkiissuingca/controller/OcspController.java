package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.service.OcspResponderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
public class OcspController {

    private static final Logger log = LoggerFactory.getLogger(OcspController.class);

    @Autowired
    private OcspResponderService ocspResponderService;

    @PostMapping(value = "/api/v1/ocsp/{caSerial}", consumes = "application/ocsp-request", produces = "application/ocsp-response")
    public ResponseEntity<byte[]> handleOcspPost(@PathVariable String caSerial, @RequestBody byte[] requestBytes) {
        try {
            byte[] responseBytes = ocspResponderService.handleRequest(requestBytes, caSerial);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/ocsp-response"))
                    .body(responseBytes);
        } catch (Exception e) {
            log.error("Error processing OCSP POST request for CA serial {}: {}", caSerial, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping(value = "/api/v1/ocsp/{caSerial}/{base64Req}", produces = "application/ocsp-response")
    public ResponseEntity<byte[]> handleOcspGet(@PathVariable String caSerial, @PathVariable String base64Req) {
        try {
            byte[] requestBytes = Base64.getUrlDecoder().decode(base64Req);
            byte[] responseBytes = ocspResponderService.handleRequest(requestBytes, caSerial);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/ocsp-response"))
                    .body(responseBytes);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid base64url encoding in OCSP GET request for CA serial {}", caSerial);
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("Error processing OCSP GET request for CA serial {}: {}", caSerial, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/api/v1/ca/{caSerial}/ocsp-signer/issue")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN')")
    public ResponseEntity<?> issueOcspSignerManually(@PathVariable String caSerial) {
        try {
            var signerEntity = ocspResponderService.issueOcspSignerCertificate(caSerial, "ADMIN");
            return ResponseEntity.ok(signerEntity);
        } catch (Exception e) {
            log.error("Manual OCSP Signer issuance failed for CA serial {}: {}", caSerial, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to issue OCSP Signer certificate: " + e.getMessage());
        }
    }
}
