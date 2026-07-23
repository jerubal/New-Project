-- V3__add_ocsp_support.sql

CREATE TABLE IF NOT EXISTS ocsp_signers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ca_certificate_id BIGINT NOT NULL,
    signer_certificate_id BIGINT NOT NULL,
    key_pair_id BIGINT NOT NULL,
    status VARCHAR(255) NOT NULL DEFAULT 'ACTIVE',
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_ocsp_ca_cert FOREIGN KEY (ca_certificate_id) REFERENCES certificates (id) ON DELETE CASCADE,
    CONSTRAINT fk_ocsp_signer_cert FOREIGN KEY (signer_certificate_id) REFERENCES certificates (id) ON DELETE CASCADE,
    CONSTRAINT fk_ocsp_key_pair FOREIGN KEY (key_pair_id) REFERENCES key_pairs (id) ON DELETE CASCADE
);

CREATE INDEX idx_ocsp_signers_ca ON ocsp_signers (ca_certificate_id, status);
