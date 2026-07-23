package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.CrlEntity;
import java.util.List;
import java.util.Optional;

public interface CrlGenerationService {

    /**
     * Generates a new CRL for the specified CA, persists it, and returns the entity.
     */
    CrlEntity generateCrl(Long caCertificateId) throws Exception;

    /**
     * Retrieves the most recent CRL for the specified CA serial number.
     */
    Optional<CrlEntity> getLatestCrlByCaSerial(String caSerialNumber);

    /**
     * Retrieves historical CRLs for the specified CA serial number.
     */
    List<CrlEntity> getCrlHistoryByCaSerial(String caSerialNumber);
}
