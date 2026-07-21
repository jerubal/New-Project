package org.insa.pkiissuingca.model;

import jakarta.persistence.*;

@Entity
@Table(name = "certificate_profiles")
public class CertificateProfileEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;

    private String description;

    @Column(name = "key_usage")
    private String keyUsage; // comma-separated strings of KeyUsage flags

    @Column(name = "extended_key_usage")
    private String extendedKeyUsage; // comma-separated strings of EKU flags/OIDs

    @Column(name = "basic_constraints")
    private boolean basicConstraints; // true for CA

    @Column(name = "path_len_constraint")
    private Integer pathLenConstraint; // path length constraint for basic constraints

    @Column(name = "validity_days", nullable = false)
    private Integer validityDays;

    @Column(name = "signature_algorithm", nullable = false)
    private String signatureAlgorithm; // SHA256withRSA, SHA256withECDSA, etc.

    public CertificateProfileEntity() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
    }

    public String getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    public void setExtendedKeyUsage(String extendedKeyUsage) {
        this.extendedKeyUsage = extendedKeyUsage;
    }

    public boolean isBasicConstraints() {
        return basicConstraints;
    }

    public void setBasicConstraints(boolean basicConstraints) {
        this.basicConstraints = basicConstraints;
    }

    public Integer getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setPathLenConstraint(Integer pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

    public Integer getValidityDays() {
        return validityDays;
    }

    public void setValidityDays(Integer validityDays) {
        this.validityDays = validityDays;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }
}
