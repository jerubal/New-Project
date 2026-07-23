package org.insa.pkiissuingca.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class KeyGenerateRequest {

    @NotBlank(message = "Key algorithm is required")
    @Pattern(regexp = "(?i)RSA|EC|ECDSA|Ed25519", message = "Algorithm must be one of RSA, EC, ECDSA, or Ed25519")
    private String algorithm;

    private Integer keySize; // 2048, 3072, 4096 or curve index/size (256, 384, 521)

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }
}
