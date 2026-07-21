package org.insa.pkiissuingca.dto;

import lombok.Data;

@Data
public class RevokeRequest {
    private String reason;
}
