package org.insa.pkiissuingca.dto;

import jakarta.validation.constraints.NotBlank;

public class RevokeRequest {

    @NotBlank(message = "Revocation reason is required")
    private String reason;

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}
