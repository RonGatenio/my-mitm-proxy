#!/usr/bin/env bash
# Generate a CA + a leaf cert for the test server C.
# Usage: gen-certs.sh <out_dir>
set -euo pipefail

OUT="${1:?usage: gen-certs.sh <out_dir>}"
mkdir -p "$OUT"

CA_CERT="$OUT/ca.pem"
CA_KEY="$OUT/ca.key"
LEAF_CERT="$OUT/leaf.pem"
LEAF_KEY="$OUT/leaf.key"
SAN="subjectAltName=IP:10.10.2.10,DNS:server.test"

# 1. CA
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$CA_KEY" -out "$CA_CERT" \
  -subj "/CN=mymitm-test-ca" >/dev/null 2>&1

# 2. Leaf CSR
openssl req -newkey rsa:2048 -nodes \
  -keyout "$LEAF_KEY" -out "$OUT/leaf.csr" \
  -subj "/CN=server.test" >/dev/null 2>&1

# 3. Sign leaf with the CA, embedding the SAN.
openssl x509 -req -in "$OUT/leaf.csr" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -days 825 -extfile <(printf '%s\n' "$SAN") \
  -out "$LEAF_CERT" >/dev/null 2>&1

rm -f "$OUT/leaf.csr" "$OUT/ca.srl"
echo "wrote: $CA_CERT $CA_KEY $LEAF_CERT $LEAF_KEY"
