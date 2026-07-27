package org.insa.pkiissuingca.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "certificates")
public class CertificateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_ca_id", foreignKey = @ForeignKey(name = "fk_cert_parent_ca"))
    @JsonIgnoreProperties({"parentCa", "childCertificates"})
    private CertificateEntity parentCa;

    @OneToMany(mappedBy = "parentCa", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<CertificateEntity> childCertificates = new ArrayList<>();


    @Column(name = "serial_number", unique = true, nullable = false)
    private String serialNumber;

    @Column(name = "subject_dn", nullable = false)
    private String subjectDN;

    @Column(name = "issuer_dn", nullable = false)
    private String issuerDN;

    @Column(name = "not_before", nullable =  true)
    private Instant notBefore;

    @Column(name = "not_after", nullable = true)
    private Instant notAfter;

    @Lob
    @Column(name = "public_key_pem", nullable = false, columnDefinition = "TEXT")
    private String publicKeyPEM;

    @Column(nullable = false)
    private String status;

    @Column(name = "revocation_reason")
    private String revocationReason;

    @Column(name = "revocation_date")
    private Instant revocationDate;

    @Lob
    @Column(name = "pem_content", nullable = false, columnDefinition = "TEXT")
    private String pemContent;

    @Column(name = "certificate_type")
    private String certificateType;

    @Column(name = "profile_name", nullable = false)
    private String profileName;

    public CertificateEntity() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public Instant getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
        this.notBefore = notBefore;
    }

    public Instant getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
        this.notAfter = notAfter;
    }

    public String getPublicKeyPEM() {
        return publicKeyPEM;
    }

    public void setPublicKeyPEM(String publicKeyPEM) {
        this.publicKeyPEM = publicKeyPEM;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public Instant getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Instant revocationDate) {
        this.revocationDate = revocationDate;
    }

    public String getPemContent() {
        return pemContent;
    }

    public void setPemContent(String pemContent) {
        this.pemContent = pemContent;
    }

    public String getCertificateType() {
        return certificateType;
    }

    public void setCertificateType(String certificateType) {
        this.certificateType = certificateType;
    }

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }

    @Column(name = "next_crl_number", nullable = false)
    private Long nextCrlNumber = 1L;

    public Long getNextCrlNumber() {
        return nextCrlNumber;
    }

    public void setNextCrlNumber(Long nextCrlNumber) {
        this.nextCrlNumber = nextCrlNumber;
    }

    public CertificateEntity getParentCa() {
        return parentCa;
    }

    public void setParentCa(CertificateEntity parentCa) {
        this.parentCa = parentCa;
    }

    public List<CertificateEntity> getChildCertificates() {
        return childCertificates;
    }

    public void setChildCertificates(List<CertificateEntity> childCertificates) {
        this.childCertificates = childCertificates;
    }
}