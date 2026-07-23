package org.insa.pkiissuingca.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class KeystoreExportRequest {

    @NotBlank(message = "Certificate serial number is required")
    private String serialNumber;

    @NotNull(message = "KeyPair ID is required")
    private Long keyId;

    @NotBlank(message = "Keystore password is required")
    private String password;

    private String alias;

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
