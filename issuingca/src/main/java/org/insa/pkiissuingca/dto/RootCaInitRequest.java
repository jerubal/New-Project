package org.insa.pkiissuingca.dto;

import lombok.Data;

@Data
public class RootCaInitRequest {
    private String subjectDN;
    private String keyType; // RSA, EC, Ed25519
    private int keySizeOrCurve; // 2048, 3072, 4096, 256, 384, 521
    private String profileName; // e.g. RootCA
}
