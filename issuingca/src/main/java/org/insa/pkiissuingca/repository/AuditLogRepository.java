package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.AuditLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntity, Long> {
    
    // Find the latest audit log entry by ID to chain the hash
    Optional<AuditLogEntity> findFirstByOrderByIdDesc();
}
