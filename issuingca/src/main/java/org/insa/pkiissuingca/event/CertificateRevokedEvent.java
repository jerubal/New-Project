package org.insa.pkiissuingca.event;

public class CertificateRevokedEvent {

    private final String serialNumber;
    private final Long parentCaId;
    private final String reason;

    public CertificateRevokedEvent(String serialNumber, Long parentCaId, String reason) {
        this.serialNumber = serialNumber;
        this.parentCaId = parentCaId;
        this.reason = reason;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public Long getParentCaId() {
        return parentCaId;
    }

    public String getReason() {
        return reason;
    }
}
