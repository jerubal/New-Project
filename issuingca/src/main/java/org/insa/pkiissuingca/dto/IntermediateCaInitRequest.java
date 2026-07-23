package org.insa.pkiissuingca.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class IntermediateCaInitRequest {

    @NotBlank(message = "Subject DN is required")
    private String subjectDN;

    @NotBlank(message = "Parent serial number is required")
    private String parentSerialNumber;

    @NotBlank(message = "Key type is required")
    @Pattern(regexp = "(?i)RSA|EC|ECDSA|Ed25519", message = "Key type must be RSA, EC, ECDSA, or Ed25519")
    private String keyType;

    @Min(value = 256, message = "Key size or curve must be at least 256")
    private int keySizeOrCurve;

    private String profileName; // e.g. SubCA

    private Integer pathLenConstraint;

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getParentSerialNumber() {
        return parentSerialNumber;
    }

    public void setParentSerialNumber(String parentSerialNumber) {
        this.parentSerialNumber = parentSerialNumber;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public int getKeySizeOrCurve() {
        return keySizeOrCurve;
    }

    public void setKeySizeOrCurve(int keySizeOrCurve) {
        this.keySizeOrCurve = keySizeOrCurve;
    }

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }

    public Integer getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setPathLenConstraint(Integer pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }
}
