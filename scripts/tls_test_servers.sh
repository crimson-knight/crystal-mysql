#!/usr/bin/env bash
# Starts the MySQL servers the TLS specs (spec/tls_spec.cr) run against:
#
#   port 3306  the server under test, TLS 1.2 and 1.3, with a certificate for
#              127.0.0.1 and localhost signed by a CA made here
#   port 3312  the same image limited to TLS 1.2, for the TLS 1.3 error
#
# Usage: scripts/tls_test_servers.sh IMAGE CERT_DIR
#   IMAGE     mysql:<version>@sha256:<digest> (always pin the digest)
#   CERT_DIR  where the CA and server certificate are written
# Prints the environment the specs need. Stop the servers with
#   docker rm -f crystal-mysql-tls crystal-mysql-tls12
set -euo pipefail

image=$1
cert_dir=$2
mkdir -p "$cert_dir"
cd "$cert_dir"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=crystal-mysql TLS spec CA" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
printf '%s\n' \
  "subjectAltName = DNS:localhost, IP:127.0.0.1" \
  "keyUsage = critical, digitalSignature" \
  "extendedKeyUsage = serverAuth" \
  "basicConstraints = critical, CA:FALSE" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 30 -extfile server.ext -out server.pem 2>/dev/null
# The server reads its key as the mysql user inside the container.
chmod 644 ca.pem server.pem server.key

docker rm -f crystal-mysql-tls crystal-mysql-tls12 >/dev/null 2>&1 || true
common=(-e MYSQL_ALLOW_EMPTY_PASSWORD=yes -v "$PWD:/certs:ro")
tls_args=(--ssl-ca=/certs/ca.pem --ssl-cert=/certs/server.pem --ssl-key=/certs/server.key)
docker run -d --name crystal-mysql-tls -p 127.0.0.1:3306:3306 "${common[@]}" "$image" \
  "${tls_args[@]}" --tls-version=TLSv1.2,TLSv1.3 >/dev/null
docker run -d --name crystal-mysql-tls12 -p 127.0.0.1:3312:3306 "${common[@]}" "$image" \
  "${tls_args[@]}" --tls-version=TLSv1.2 >/dev/null

for name in crystal-mysql-tls crystal-mysql-tls12; do
  for _ in $(seq 1 90); do
    if docker exec "$name" mysql -uroot -h127.0.0.1 -e "SELECT 1" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  docker exec "$name" mysql -uroot -h127.0.0.1 -e "SELECT VERSION(), @@tls_version" >&2
done

echo "DATABASE_HOST=127.0.0.1"
echo "MYSQL_TLS_CA=$PWD/ca.pem"
echo "MYSQL_TLS12_URL=mysql://root@127.0.0.1:3312"
