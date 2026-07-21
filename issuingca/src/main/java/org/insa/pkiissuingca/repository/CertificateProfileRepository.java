package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.CertificateProfileEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface CertificateProfileRepository extends JpaRepository<CertificateProfileEntity, Long> {
    Optional<CertificateProfileEntity> findByName(String name);
}
