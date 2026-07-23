package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.CrlEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CrlRepository extends JpaRepository<CrlEntity, Long> {
    Optional<CrlEntity> findFirstByCaCertificateIdOrderByThisUpdateDesc(Long caCertificateId);
    List<CrlEntity> findByCaCertificateIdOrderByThisUpdateDesc(Long caCertificateId);
}
