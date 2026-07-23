package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.dto.CachedCertStatus;

public interface ValidationCacheService {

    /**
     * Retrieves cached certificate status from Redis.
     */
    CachedCertStatus getCertStatus(String serialNumber);

    /**
     * Caches certificate status in Redis with configured TTL.
     */
    void putCertStatus(CachedCertStatus status);

    /**
     * Immediately evicts certificate status and OCSP responses for serial from Redis cache.
     */
    void evictCertStatus(String serialNumber);

    /**
     * Retrieves cached raw OCSP response byte payload.
     */
    byte[] getOcspResponse(String cacheKey);

    /**
     * Stores raw OCSP response byte payload in Redis with TTL.
     */
    void putOcspResponse(String cacheKey, byte[] ocspResponseBytes, long ttlSeconds);
}
