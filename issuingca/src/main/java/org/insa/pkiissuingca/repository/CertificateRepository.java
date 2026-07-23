package org.insa.pkiissuingca.repository;

import jakarta.persistence.LockModeType;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
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

    /**
     * Loads the CA row with a pessimistic write lock (SELECT ... FOR UPDATE), held for the
     * remainder of the enclosing transaction. Use this — not findById — whenever a caller is
     * about to read nextCrlNumber and increment it, so two concurrent CRL-generation
     * transactions for the same CA are serialized by the DB instead of racing to read the
     * same starting value. The previous approach (read nextCrlNumber via findById, then fire
     * a separate bulk UPDATE ... SET nextCrlNumber = nextCrlNumber + 1) let two transactions
     * both observe the same pre-increment value before either committed; a unique constraint
     * on (ca_certificate_id, crl_number) caught the resulting duplicate as an insert failure,
     * but that's a safety net, not a fix — the losing transaction's work was wasted and the
     * failure surfaced as a generic DB exception instead of being prevented up front.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM CertificateEntity c WHERE c.id = :id")
    Optional<CertificateEntity> findByIdForUpdate(@Param("id") Long id);
}

