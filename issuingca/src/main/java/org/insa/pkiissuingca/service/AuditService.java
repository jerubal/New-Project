package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.AuditLogEntity;
import org.insa.pkiissuingca.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Optional;

@Service
public class AuditService {

    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);
    private static final String GENESIS_SALT = "CA_GENESIS_SALT_2026_INIT";

    @Autowired
    private AuditLogRepository auditLogRepository;

    /**
     * Creates, links (by hash chain), and saves an append-only audit log entry.
     */
    @Transactional
    public AuditLogEntity log(String username, String action, String details, String status, String ipAddress) {
        AuditLogEntity entry = new AuditLogEntity();
        entry.setTimestamp(Instant.now());
        entry.setUsername(username != null ? username : "SYSTEM");
        entry.setAction(action);
        entry.setDetails(details);
        entry.setStatus(status);
        entry.setIpAddress(ipAddress != null ? ipAddress : "127.0.0.1");

        // Calculate Chained Checksum to enforce immutable append-only record integrity
        try {
            Optional<AuditLogEntity> latestLog = auditLogRepository.findFirstByOrderByIdDesc();
            String prevChecksum = latestLog.map(AuditLogEntity::getChecksum).orElse(GENESIS_SALT);

            String combinedString = prevChecksum +
                    entry.getTimestamp().toString() +
                    entry.getUsername() +
                    entry.getAction() +
                    entry.getDetails() +
                    entry.getStatus() +
                    entry.getIpAddress();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combinedString.getBytes(StandardCharsets.UTF_8));
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            entry.setChecksum(hexString.toString());
        } catch (Exception e) {
            logger.error("Failed to compute tamper-evident audit log checksum", e);
            entry.setChecksum("COMPUTE_ERROR");
        }

        AuditLogEntity saved = auditLogRepository.save(entry);

        // Structured output for Logstash / Fluentd SIEM ingestion
        logger.info("[AUDIT_LOG] ID={}, Timestamp={}, User={}, Action={}, Status={}, IP={}, Checksum={}",
                saved.getId(), saved.getTimestamp(), saved.getUsername(), saved.getAction(),
                saved.getStatus(), saved.getIpAddress(), saved.getChecksum());

        return saved;
    }
}
