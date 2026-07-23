package org.insa.pkiissuingca.dto;

import jakarta.validation.constraints.NotBlank;

public class CsrSignRequest {

    @NotBlank(message = "CSR PEM content is required")
    private String csrPem;

    @NotBlank(message = "CA serial number is required")
    private String caSerialNumber;

    private String profileName; // e.g. Client, Server

    public String getCsrPem() {
        return csrPem;
    }

    public void setCsrPem(String csrPem) {
        this.csrPem = csrPem;
    }

    public String getCaSerialNumber() {
        return caSerialNumber;
    }

    public void setCaSerialNumber(String caSerialNumber) {
        this.caSerialNumber = caSerialNumber;
    }

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }
}
