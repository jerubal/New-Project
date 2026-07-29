# PKI Certificate Issuing CA Portal

An enterprise-grade, high-availability Public Key Infrastructure (PKI) Certificate Authority (CA) system with integrated Hardware Security Module (HSM) support, real-time revocation services (OCSP/CRL), and a React-based hierarchical CA visualizer.

---

## 🚀 Key Features

* **Complete CA Lifecycle Management:** Initializing self-signed Root CAs, subordinate/intermediate CAs, and parsing/signing CSRs for end-entity certificates.
* **PKCS#11 HSM Cryptographic Offloading:** Hardware key pair generation (RSA/EC) and offloaded cryptographic signing (using SunPKCS11 and SoftHSM v2), ensuring CA private keys never leave the hardware boundary.
* **High-Availability (HA) Design:** Multiple API nodes load-balanced behind Nginx with database-level pessimistic locking for race-condition prevention.
* **Separation of Concerns (Dedicated OCSP Responder):** A dedicated, public-facing OCSP node optimized for high-throughput validation caching via Redis, separated from the sensitive CA administration endpoints.
* **Automated CRL Management:** Scheduled background regeneration and event-driven updates.
* **Directory Publishing:** Automatic publishing of issued certificates to directory services via LDAP.
* **Interactive Frontend:** A modern React dashboard featuring an interactive hierarchical chain tree view of the CA topology.

---

## 🛠️ Technology Stack

* **Backend:** Java 25, Spring Boot 3.4.0, Spring Security (JWT)
* **Frontend:** React, Vite, CSS
* **Database & Cache:** MariaDB 11.4, Redis 7.4 (Alpine)
* **Reverse Proxy & Load Balancer:** Nginx 1.27
* **Cryptography:** BouncyCastle Provider (`bcpkix-jdk18on`)
* **HSM Emulation:** SoftHSM v2 (using PKCS#11)
* **Orchestration:** Docker & Docker Compose v2+

---

## 📦 Deployment Topology

The Docker Compose setup deploys a fully isolated network (`pki_net`):

```
                     Internet / Host
                            │
                            ▼
                    [Nginx Load Balancer] (Port 80/443)
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
       [app_node1]     [app_node2]     [ocsp_node]
        (Port 8080)     (Port 8080)     (Port 8080)
            │               │               │
            └───────┬───────┴───────────────┤
                    ▼                       ▼
            [MariaDB Database]       [Redis Cache]
               (Port 3306)            (Port 6379)
```

---

## ⚙️ Quick Start

### 1. Prerequisites
Ensure you have Docker and Docker Compose v2+ installed.

### 2. Configure Environment Secrets
Create a `.env` file at the root of the project. You can generate random secure secrets using the following commands:
```bash
# Generate keys
echo "JWT_SECRET=$(openssl rand -base64 32)"
echo "PKI_DB_ENCRYPTION_KEY=$(openssl rand -base64 32)"
echo "DB_ROOT_PASSWORD=$(openssl rand -base64 24)"
echo "DB_PASSWORD=$(openssl rand -base64 24)"
echo "REDIS_PASSWORD=$(openssl rand -base64 24)"
```
Configure your `.env` values, ensuring `HSM_PIN` and `HSM_SO_PIN` are set to strong secure values.

### 3. Generate Dev TLS Certificates for Nginx
```bash
# Run the dev certificate script
bash docker/nginx/generate-dev-cert.sh
```

### 4. Build and Run the Stack
```bash
docker-compose up -d --build
```

Access the UI at `https://localhost` (or your host IP).

---

## 🛡️ Security Boundaries & Policies

### CSR Policy Rules
All incoming CSRs are strictly validated programmatically in `CsrService.java`:
- Proof-of-Possession is checked by verifying the request signature.
- Weak hashing algorithms (MD2, MD4, MD5, SHA-1) are rejected outright.
- Minimum key sizes are strictly enforced: RSA $\ge 2048$ bits, EC $\ge 256$ bits.

### HSM Private Key Isolation
CA Private keys never enter the JVM memory space when HSM is enabled. 
- During generation, keys are instantiated directly on the HSM token.
- The database stores a reference alias `HSM:<serial_number>`.
- Cryptographic signatures are offloaded to the PKCS#11 library using key handles.
