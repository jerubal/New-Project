package org.insa.pkiissuingca.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "crls", uniqueConstraints = {
        @UniqueConstraint(name = "uk_crls_ca_crl_number", columnNames = {"ca_certificate_id", "crl_number"})
}, indexes = {
        @Index(name = "idx_crls_ca_this_update", columnList = "ca_certificate_id, this_update DESC")
})
public class CrlEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_certificate_id", nullable = false, foreignKey = @ForeignKey(name = "fk_crls_ca_cert"))
    @JsonIgnore
    private CertificateEntity caCertificate;

    @Column(name = "crl_number", nullable = false)
    private Long crlNumber;

    @Column(name = "this_update", nullable = false)
    private Instant thisUpdate;

    @Column(name = "next_update", nullable = false)
    private Instant nextUpdate;

    @Lob
    @Column(name = "der_content", nullable = false, columnDefinition = "LONGBLOB")
    @JsonIgnore
    private byte[] derContent;

    @Lob
    @Column(name = "pem_content", nullable = false, columnDefinition = "TEXT")
    private String pemContent;

    @Column(name = "revoked_count", nullable = false)
    private Integer revokedCount;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public CrlEntity() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public CertificateEntity getCaCertificate() { return caCertificate; }
    public void setCaCertificate(CertificateEntity caCertificate) { this.caCertificate = caCertificate; }

    public Long getCrlNumber() { return crlNumber; }
    public void setCrlNumber(Long crlNumber) { this.crlNumber = crlNumber; }

    public Instant getThisUpdate() { return thisUpdate; }
    public void setThisUpdate(Instant thisUpdate) { this.thisUpdate = thisUpdate; }

    public Instant getNextUpdate() { return nextUpdate; }
    public void setNextUpdate(Instant nextUpdate) { this.nextUpdate = nextUpdate; }

    public byte[] getDerContent() { return derContent; }
    public void setDerContent(byte[] derContent) { this.derContent = derContent; }

    public String getPemContent() { return pemContent; }
    public void setPemContent(String pemContent) { this.pemContent = pemContent; }

    public Integer getRevokedCount() { return revokedCount; }
    public void setRevokedCount(Integer revokedCount) { this.revokedCount = revokedCount; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
