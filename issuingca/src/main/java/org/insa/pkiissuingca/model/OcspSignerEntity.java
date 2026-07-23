package org.insa.pkiissuingca.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "ocsp_signers")
public class OcspSignerEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_certificate_id", nullable = false, foreignKey = @ForeignKey(name = "fk_ocsp_ca_cert"))
    @JsonIgnore
    private CertificateEntity caCertificate;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "signer_certificate_id", nullable = false, foreignKey = @ForeignKey(name = "fk_ocsp_signer_cert"))
    private CertificateEntity signerCertificate;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_pair_id", nullable = false, foreignKey = @ForeignKey(name = "fk_ocsp_key_pair"))
    @JsonIgnore
    private KeyPairEntity keyPair;

    @Column(nullable = false)
    private String status = "ACTIVE"; // ACTIVE, EXPIRED, REVOKED

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    public OcspSignerEntity() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public CertificateEntity getCaCertificate() { return caCertificate; }
    public void setCaCertificate(CertificateEntity caCertificate) { this.caCertificate = caCertificate; }

    public CertificateEntity getSignerCertificate() { return signerCertificate; }
    public void setSignerCertificate(CertificateEntity signerCertificate) { this.signerCertificate = signerCertificate; }

    public KeyPairEntity getKeyPair() { return keyPair; }
    public void setKeyPair(KeyPairEntity keyPair) { this.keyPair = keyPair; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
}
