package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.OcspSignerEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OcspSignerRepository extends JpaRepository<OcspSignerEntity, Long> {
    Optional<OcspSignerEntity> findFirstByCaCertificateIdAndStatusOrderByCreatedAtDesc(Long caCertificateId, String status);
    List<OcspSignerEntity> findByCaCertificateIdOrderByCreatedAtDesc(Long caCertificateId);
}
