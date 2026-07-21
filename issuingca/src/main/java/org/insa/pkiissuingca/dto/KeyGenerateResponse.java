package org.insa.pkiissuingca.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class KeyGenerateResponse {
    private String algorithm;
    private Integer keySize;
    private String status;
    private String message;
    // Add other fields you need, but do not include User or Role entities here
}