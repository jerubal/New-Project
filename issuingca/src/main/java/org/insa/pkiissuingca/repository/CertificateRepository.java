package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.List;

@Repository
public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {
    Optional<CertificateEntity> findBySerialNumber(String serialNumber);
    List<CertificateEntity> findBySubjectDN(String subjectDN);
    List<CertificateEntity> findByStatus(String status);
}
