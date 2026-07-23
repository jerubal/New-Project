-- V2__add_crl_support.sql

ALTER TABLE certificates ADD COLUMN next_crl_number BIGINT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS crls (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ca_certificate_id BIGINT NOT NULL,
    crl_number BIGINT NOT NULL,
    this_update DATETIME(6) NOT NULL,
    next_update DATETIME(6) NOT NULL,
    der_content LONGBLOB NOT NULL,
    pem_content TEXT NOT NULL,
    revoked_count INT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_crls_ca_cert FOREIGN KEY (ca_certificate_id) REFERENCES certificates (id) ON DELETE CASCADE,
    CONSTRAINT uk_crls_ca_crl_number UNIQUE (ca_certificate_id, crl_number)
);

CREATE INDEX idx_crls_ca_this_update ON crls (ca_certificate_id, this_update DESC);
