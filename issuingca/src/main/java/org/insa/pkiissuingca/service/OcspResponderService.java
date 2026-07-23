package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.OcspSignerEntity;

public interface OcspResponderService {

    /**
     * Handles an incoming RFC 6960 OCSP request in raw DER format and produces signed OCSP response DER bytes.
     */
    byte[] handleRequest(byte[] ocspRequestDer, String caSerial) throws Exception;

    /**
     * Issues or renews a dedicated short-lived OCSP signer certificate for the given CA.
     */
    OcspSignerEntity issueOcspSignerCertificate(String caSerial, String username) throws Exception;
}
