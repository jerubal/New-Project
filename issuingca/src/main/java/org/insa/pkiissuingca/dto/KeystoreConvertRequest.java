package org.insa.pkiissuingca.dto;

import jakarta.validation.constraints.NotBlank;

public class KeystoreConvertRequest {

    @NotBlank(message = "Source keystore data (Base64) is required")
    private String sourceKeystoreBase64;

    @NotBlank(message = "Source keystore type is required (e.g., JKS or PKCS12)")
    private String sourceType;

    private String sourcePassword;

    @NotBlank(message = "Target keystore type is required (e.g., PKCS12 or JKS)")
    private String targetType;

    @NotBlank(message = "Target keystore password is required")
    private String targetPassword;

    public String getSourceKeystoreBase64() {
        return sourceKeystoreBase64;
    }

    public void setSourceKeystoreBase64(String sourceKeystoreBase64) {
        this.sourceKeystoreBase64 = sourceKeystoreBase64;
    }

    public String getSourceType() {
        return sourceType;
    }

    public void setSourceType(String sourceType) {
        this.sourceType = sourceType;
    }

    public String getSourcePassword() {
        return sourcePassword;
    }

    public void setSourcePassword(String sourcePassword) {
        this.sourcePassword = sourcePassword;
    }

    public String getTargetType() {
        return targetType;
    }

    public void setTargetType(String targetType) {
        this.targetType = targetType;
    }

    public String getTargetPassword() {
        return targetPassword;
    }

    public void setTargetPassword(String targetPassword) {
        this.targetPassword = targetPassword;
    }
}
