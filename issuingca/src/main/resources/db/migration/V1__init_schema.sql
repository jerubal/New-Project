-- Initial DB Schema Migration for PKI Issuing CA Portal

CREATE TABLE IF NOT EXISTS roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    enabled BIT(1) NOT NULL DEFAULT 1,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    uuid VARCHAR(255) NOT NULL,
    is_soft_deleted BIT(1) NOT NULL DEFAULT 0,
    mfa_enabled BIT(1) NOT NULL DEFAULT 0,
    requires_password_change BIT(1) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS key_pairs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    algorithm VARCHAR(255) NOT NULL,
    key_size INT,
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    user_id BIGINT NOT NULL,
    CONSTRAINT fk_key_pairs_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certificates (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    parent_ca_id BIGINT,
    serial_number VARCHAR(255) NOT NULL UNIQUE,
    subject_dn VARCHAR(255) NOT NULL,
    issuer_dn VARCHAR(255) NOT NULL,
    not_before DATETIME(6),
    not_after DATETIME(6),
    public_key_pem TEXT NOT NULL,
    status VARCHAR(255) NOT NULL,
    revocation_reason VARCHAR(255),
    revocation_date DATETIME(6),
    pem_content TEXT NOT NULL,
    certificate_type VARCHAR(255),
    profile_name VARCHAR(255) NOT NULL,
    CONSTRAINT fk_cert_parent_ca FOREIGN KEY (parent_ca_id) REFERENCES certificates (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS certificate_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(255),
    key_usage VARCHAR(255),
    extended_key_usage VARCHAR(255),
    basic_constraints BIT(1) NOT NULL,
    path_len_constraint INT,
    validity_days INT NOT NULL,
    signature_algorithm VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS keystores (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(255) NOT NULL,
    keystore_bytes LONGBLOB NOT NULL,
    created_at DATETIME(6) NOT NULL,
    user_id BIGINT NOT NULL,
    CONSTRAINT fk_keystores_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME(6) NOT NULL,
    username VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    ip_address VARCHAR(255),
    status VARCHAR(255) NOT NULL,
    checksum VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS user_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL,
    mfa_secret VARCHAR(255),
    mfa_enabled BIT(1) NOT NULL DEFAULT 0,
    enabled BIT(1) NOT NULL DEFAULT 1
);
