package org.insa.pkiissuingca.dto;

import lombok.Data;

@Data
public class CsrSignRequest {
    private String csrPem;
    private String caSerialNumber;
    private String profileName; // e.g. Client, Server
}
