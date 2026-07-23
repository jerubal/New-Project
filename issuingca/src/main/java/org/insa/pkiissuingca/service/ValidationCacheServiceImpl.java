package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.dto.CachedCertStatus;
import org.insa.pkiissuingca.event.CertificateRevokedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class ValidationCacheServiceImpl implements ValidationCacheService {

    private static final Logger log = LoggerFactory.getLogger(ValidationCacheServiceImpl.class);
    private static final String CERT_STATUS_PREFIX = "certstatus:";
    private static final String OCSP_RESP_PREFIX = "ocspresp:";

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    @Value("${cache.cert-status-ttl-seconds:300}")
    private long certStatusTtlSeconds;

    @Value("${cache.ocsp-response-ttl-seconds:300}")
    private long ocspResponseTtlSeconds;

    @Override
    public CachedCertStatus getCertStatus(String serialNumber) {
        if (redisTemplate == null) return null;
        try {
            String key = CERT_STATUS_PREFIX + serialNumber;
            Object val = redisTemplate.opsForValue().get(key);
            if (val instanceof CachedCertStatus) {
                return (CachedCertStatus) val;
            }
        } catch (Exception e) {
            log.warn("Redis getCertStatus failed for serial {}: {}", serialNumber, e.getMessage());
        }
        return null;
    }

    @Override
    public void putCertStatus(CachedCertStatus status) {
        if (redisTemplate == null || status == null) return;
        try {
            String key = CERT_STATUS_PREFIX + status.getSerialNumber();
            redisTemplate.opsForValue().set(key, status, Duration.ofSeconds(certStatusTtlSeconds));
        } catch (Exception e) {
            log.warn("Redis putCertStatus failed for serial {}: {}", status.getSerialNumber(), e.getMessage());
        }
    }

    @Override
    public void evictCertStatus(String serialNumber) {
        if (redisTemplate == null || serialNumber == null) return;
        try {
            String certKey = CERT_STATUS_PREFIX + serialNumber;
            redisTemplate.delete(certKey);
            // Evict matching OCSP response keys if present
            var keys = redisTemplate.keys(OCSP_RESP_PREFIX + "*:" + serialNumber + ":*");
            if (keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
            }
            log.info("Evicted Redis validation cache entries for serial: {}", serialNumber);
        } catch (Exception e) {
            log.warn("Redis evictCertStatus failed for serial {}: {}", serialNumber, e.getMessage());
        }
    }

    @Override
    public byte[] getOcspResponse(String cacheKey) {
        if (redisTemplate == null) return null;
        try {
            String key = OCSP_RESP_PREFIX + cacheKey;
            Object val = redisTemplate.opsForValue().get(key);
            if (val instanceof byte[]) {
                return (byte[]) val;
            }
        } catch (Exception e) {
            log.warn("Redis getOcspResponse failed for key {}: {}", cacheKey, e.getMessage());
        }
        return null;
    }

    @Override
    public void putOcspResponse(String cacheKey, byte[] ocspResponseBytes, long ttlSeconds) {
        if (redisTemplate == null || ocspResponseBytes == null) return;
        try {
            String key = OCSP_RESP_PREFIX + cacheKey;
            long effectiveTtl = ttlSeconds > 0 ? Math.min(ttlSeconds, ocspResponseTtlSeconds) : ocspResponseTtlSeconds;
            redisTemplate.opsForValue().set(key, ocspResponseBytes, Duration.ofSeconds(effectiveTtl));
        } catch (Exception e) {
            log.warn("Redis putOcspResponse failed for key {}: {}", cacheKey, e.getMessage());
        }
    }

    @EventListener
    public void handleCertificateRevoked(CertificateRevokedEvent event) {
        log.info("Handling CertificateRevokedEvent for serial {}: Immediate Redis Cache Eviction", event.getSerialNumber());
        evictCertStatus(event.getSerialNumber());
    }
}
