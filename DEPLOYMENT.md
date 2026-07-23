# Phase 3 Deployment Guide

## Prerequisites
- Docker and Docker Compose v2+
- `openssl` for certificate and secret generation

---

## 1. Generate secrets

```bash
echo "JWT_SECRET=$(openssl rand -base64 32)"
echo "PKI_DB_ENCRYPTION_KEY=$(openssl rand -base64 32)"
echo "DB_ROOT_PASSWORD=$(openssl rand -base64 24)"
echo "DB_PASSWORD=$(openssl rand -base64 24)"
echo "REDIS_PASSWORD=$(openssl rand -base64 24)"
```

Copy the output into a `.env` file at the project root (next to `docker-compose.yml`). Add the DB_USERNAME and any LDAP/CDP/OCSP URL overrides as needed.

---

## 2. Generate the self-signed TLS certificate for Nginx

```bash
cd "issuingca 1"
bash docker/nginx/generate-dev-cert.sh
```

> **Production**: Replace `docker/nginx/certs/tls.crt` and `tls.key` with certificates from a trusted CA (Let's Encrypt, your enterprise PKI, etc.).

---

## 3. Start the full HA topology

```bash
docker-compose up -d --build
```

Services started:
| Container | Role |
|---|---|
| `pki_mariadb` | MariaDB 11.4 |
| `pki_redis` | Redis 7.4 |
| `pki_app1` | Main PKI API (instance 1) |
| `pki_app2` | Main PKI API (instance 2) |
| `pki_ocsp_node` | Dedicated OCSP Responder |
| `pki_frontend` | React UI |
| `pki_nginx` | TLS + Load Balancer |

---

## 4. Verify HA failover (kill one app instance mid-traffic)

```bash
# In one terminal, generate continuous load:
for i in $(seq 1 200); do
  curl -sk https://localhost/actuator/health -o /dev/null -w "%{http_code}\n"
  sleep 0.2
done

# In another terminal, kill app1:
docker-compose stop app1

# All requests should continue to return 200 via app2.
# Restart app1:
docker-compose start app1
```

---

## 5. Verify OCSP (once a Root CA is initialized via the API)

```bash
# Export CA cert and a leaf cert from the API, then:
openssl ocsp \
  -issuer ca.pem \
  -cert leaf.pem \
  -url https://localhost/api/v1/ocsp/<CA_SERIAL> \
  -CAfile ca.pem \
  -resp_text
```

Expected output: `Response verify OK` and `leaf.pem: good`.

---

## 6. Verify CRL

```bash
curl -sk https://localhost/api/v1/ca/<CA_SERIAL>/crl/latest.crl -o latest.crl
openssl crl -inform DER -in latest.crl -noout -text
```

Expected output: valid CRL with issuer, this/next update, and any revoked serial numbers.

---

## 7. LDAP Publishing (optional)

To enable LDAP directory publishing, set in your `.env`:

```
LDAP_ENABLED=true
LDAP_URL=ldap://your-server:389
LDAP_BASE_DN=dc=example,dc=org
LDAP_BIND_DN=cn=admin,dc=example,dc=org
LDAP_BIND_PASSWORD=your-ldap-password
```

Then restart the app instances:

```bash
docker-compose up -d app1 app2
```

---

## Architecture Diagram

```
Internet
  │
  └─► [Nginx :443] TLS termination
        ├─► /api/v1/auth/login        → (rate-limited) → [app1, app2]
        ├─► /api/v1/ocsp/*            → (rate-limited) → [ocsp_node]
        ├─► /api/v1/ca/*/crl/latest.* → (rate-limited) → [app1, app2]
        ├─► /api/*                    → least_conn      → [app1, app2]
        └─► /                         →                 → [frontend]

[app1, app2] ──► MariaDB (shared schema, Flyway migrations)
[app1, app2] ──► Redis   (shared certstatus cache)
[ocsp_node]  ──► MariaDB (read-only cert status lookups)
[ocsp_node]  ──► Redis   (cert status cache read + write)
```
