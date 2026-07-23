package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.service.CrlGenerationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/ca/{caSerial}/crl")
public class CrlController {

    private static final Logger log = LoggerFactory.getLogger(CrlController.class);

    @Autowired
    private CrlGenerationService crlGenerationService;

    @Autowired
    private org.insa.pkiissuingca.repository.CertificateRepository certificateRepository;

    @GetMapping("/latest.crl")
    public ResponseEntity<byte[]> getLatestCrlDer(@PathVariable String caSerial) {
        return crlGenerationService.getLatestCrlByCaSerial(caSerial)
                .map(crl -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + caSerial + ".crl\"")
                        .contentType(MediaType.parseMediaType("application/pkix-crl"))
                        .body(crl.getDerContent()))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/latest.pem")
    public ResponseEntity<String> getLatestCrlPem(@PathVariable String caSerial) {
        return crlGenerationService.getLatestCrlByCaSerial(caSerial)
                .map(crl -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + caSerial + ".crl.pem\"")
                        .contentType(MediaType.parseMediaType("application/x-pem-file"))
                        .body(crl.getPemContent()))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/history")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'AUDITOR', 'ROLE_CA_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<CrlEntity>> getCrlHistory(@PathVariable String caSerial) {
        List<CrlEntity> history = crlGenerationService.getCrlHistoryByCaSerial(caSerial);
        return ResponseEntity.ok(history);
    }

    @PostMapping("/generate")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN')")
    public ResponseEntity<?> generateCrlManually(@PathVariable String caSerial) {
        try {
            var caCert = certificateRepository.findBySerialNumber(caSerial)
                    .orElseThrow(() -> new IllegalArgumentException("CA certificate not found with serial: " + caSerial));

            CrlEntity crl = crlGenerationService.generateCrl(caCert.getId());
            return ResponseEntity.ok(crl);
        } catch (Exception e) {
            log.error("Manual CRL generation failed for CA serial {}: {}", caSerial, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to generate CRL: " + e.getMessage());
        }
    }
}
