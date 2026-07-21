package org.insa.pkiissuingca.dto;

import lombok.Data;

@Data
public class KeyGenerateRequest {
    private String algorithm; // RSA, EC, Ed25519
    private Integer keySize; // 2048, 3072, 4096 or curve index/size
}
