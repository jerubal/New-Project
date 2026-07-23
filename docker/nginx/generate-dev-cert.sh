#!/bin/bash
# Generate a self-signed TLS certificate for local Nginx dev usage.
# In production, replace with a cert from a trusted CA.
mkdir -p docker/nginx/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout docker/nginx/certs/tls.key \
  -out    docker/nginx/certs/tls.crt \
  -subj "/C=FR/ST=Occitanie/L=Toulouse/O=INSA/CN=localhost"
echo "Self-signed TLS certificate written to docker/nginx/certs/"
