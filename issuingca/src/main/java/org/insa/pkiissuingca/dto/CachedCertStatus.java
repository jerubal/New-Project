package org.insa.pkiissuingca.dto;

import java.io.Serializable;
import java.time.Instant;

public class CachedCertStatus implements Serializable {

    private static final long serialVersionUID = 1L;

    private String serialNumber;
    private String status; // ISSUED, REVOKED, SUSPENDED
    private String revocationReason;
    private Instant revocationDate;

    public CachedCertStatus() {}

    public CachedCertStatus(String serialNumber, String status, String revocationReason, Instant revocationDate) {
        this.serialNumber = serialNumber;
        this.status = status;
        this.revocationReason = revocationReason;
        this.revocationDate = revocationDate;
    }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getRevocationReason() { return revocationReason; }
    public void setRevocationReason(String revocationReason) { this.revocationReason = revocationReason; }

    public Instant getRevocationDate() { return revocationDate; }
    public void setRevocationDate(Instant revocationDate) { this.revocationDate = revocationDate; }
}
