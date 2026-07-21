package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.dto.KeyGenerateRequest;
import org.insa.pkiissuingca.dto.KeyGenerateResponse;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.insa.pkiissuingca.repository.UserRepository;
import org.insa.pkiissuingca.service.AuditService;
import org.insa.pkiissuingca.service.CryptoService;
import org.insa.pkiissuingca.service.SerializationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair;
import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/v1/keys")
public class KeyController {

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditService auditService;

    @PostMapping("/generate")
    public ResponseEntity<?> generateKeys(@RequestBody KeyGenerateRequest request) {
        String username = getCurrentUsername();
        User currentUser = userRepository.findByUsername(username).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).body("Authenticated user not found");
        }

        try {
            KeyPair keyPair;
            String algorithm = request.getAlgorithm();
            int keySize = request.getKeySize() != null ? request.getKeySize() : 2048;

            if ("EC".equalsIgnoreCase(algorithm) || "ECDSA".equalsIgnoreCase(algorithm)) {
                String curve = keySize == 384 ? "secp384r1" : (keySize == 521 ? "secp521r1" : "secp256r1");
                keyPair = cryptoService.generateEcKeyPair(curve);
                algorithm = "EC";
            } else if ("Ed25519".equalsIgnoreCase(algorithm)) {
                keyPair = cryptoService.generateEd25519KeyPair();
                algorithm = "Ed25519";
            } else {
                keyPair = cryptoService.generateRsaKeyPair(keySize);
                algorithm = "RSA";
            }

            KeyPairEntity keyPairEntity = new KeyPairEntity();
            keyPairEntity.setAlgorithm(algorithm);
            keyPairEntity.setKeySize(keySize);
            keyPairEntity.setPrivateKeyPEM(serializationService.convertToPem(keyPair.getPrivate()));
            keyPairEntity.setPublicKeyPEM(serializationService.convertToPem(keyPair.getPublic()));
            keyPairEntity.setCreatedAt(Instant.now());
            keyPairEntity.setUser(currentUser);

            KeyPairEntity saved = keyPairRepository.save(keyPairEntity);

            auditService.log(username, "GENERATE_KEYPAIR",
                    "Generated KeyPair ID: " + saved.getId() + ", Alg: " + algorithm + ", Size: " + keySize,
                    "SUCCESS", "127.0.0.1");

            return ResponseEntity.ok(saved);

        } catch (Exception e) {
            auditService.log(username, "GENERATE_KEYPAIR", "Error: " + e.getMessage(), "FAILURE", "127.0.0.1");
            return ResponseEntity.badRequest().body("Failed to generate key pair: " + e.getMessage());
        }
    }

    @GetMapping
    public ResponseEntity<List<KeyPairEntity>> listKeys() {
        return ResponseEntity.ok(keyPairRepository.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getKey(@PathVariable Long id) {
        String username = getCurrentUsername();
        KeyPairEntity kp = keyPairRepository.findById(id).orElse(null);
        if (kp == null) {
            return ResponseEntity.notFound().build();
        }

        User currentUser = userRepository.findByUsername(username).orElse(null);
        boolean isAuditorOrAdmin = SecurityContextHolder.getContext().getAuthentication() != null &&
                SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                        .anyMatch(a -> a.getAuthority().equals("ROLE_CA_ADMIN") || a.getAuthority().equals("ROLE_RA_OPERATOR") || a.getAuthority().equals("ROLE_AUDITOR"));

        if (!isAuditorOrAdmin && (currentUser == null || !kp.getUser().getId().equals(currentUser.getId()))) {
            return ResponseEntity.status(403).body("Access denied to requested key pair.");
        }
        return ResponseEntity.ok(kp);
    }

    @GetMapping("/generate-csr/{keyId}")
    public ResponseEntity<String> getCsrString(@PathVariable Long keyId) {
        try {
            // Retrieve existing key pair by ID to prevent duplicate generation
            KeyPairEntity kpEntity = keyPairRepository.findById(keyId)
                    .orElseThrow(() -> new RuntimeException("KeyPair not found with ID: " + keyId));

            // Reconstruct KeyPair from PEM strings using SerializationService
            KeyPair kp = serializationService.convertToKeyPair(
                    kpEntity.getPrivateKeyPEM(),
                    kpEntity.getPublicKeyPEM()
            );

            // Generate CSR using the existing key
            String csrPem = cryptoService.generateCsr(kp, "CN=TestEntity,O=INSA,C=FR");
            return ResponseEntity.ok(csrPem);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error generating CSR: " + e.getMessage());
        }
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