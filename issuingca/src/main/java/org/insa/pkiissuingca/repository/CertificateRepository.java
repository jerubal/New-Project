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
    List<CertificateEntity> findByParentCaId(Long parentCaId);
    List<CertificateEntity> findByParentCaIdAndStatusIn(Long parentCaId, List<String> statuses);
    List<CertificateEntity> findByParentCaIsNull();

    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query("UPDATE CertificateEntity c SET c.nextCrlNumber = c.nextCrlNumber + 1 WHERE c.id = :caId")
    int incrementNextCrlNumber(@org.springframework.data.repository.query.Param("caId") Long caId);
}

