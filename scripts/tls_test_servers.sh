#!/usr/bin/env bash
# Starts the MySQL servers the TLS specs (spec/tls_spec.cr) run against:
#
#   port 3306  the server under test, TLS 1.2 and 1.3, with a certificate for
#              127.0.0.1 and localhost signed by a CA made here
#   port 3312  the same image limited to TLS 1.2, for the TLS 1.3 error
#   port 3313  TLS 1.3 only with require_secure_transport=ON, trusting a
#              second CA made here for client certificates, for the
#              REQUIRE X509 / SUBJECT / ISSUER accounts
#
# Usage: scripts/tls_test_servers.sh IMAGE CERT_DIR
#   IMAGE     mysql:<version>@sha256:<digest> (always pin the digest)
#   CERT_DIR  where the CAs, the server certificate and the client
#             certificates are written
# Prints the environment the specs need. Stop the servers with
#   docker rm -f crystal-mysql-tls crystal-mysql-tls12 crystal-mysql-x509
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
  "basicConstraints = critical, CA:FALSE" \
  "authorityKeyIdentifier = keyid" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 30 -extfile server.ext -out server.pem 2>/dev/null

# Client certificates: their own CA, a client the accounts are created for,
# and a second client from the same CA with another subject.
client_ca_subject="/CN=crystal-mysql TLS spec client CA"
client_subject="/CN=crystal-mysql x509 client"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "$client_ca_subject" -keyout client-ca.key -out client-ca.pem 2>/dev/null
printf '%s\n' \
  "keyUsage = critical, digitalSignature" \
  "extendedKeyUsage = clientAuth" \
  "basicConstraints = critical, CA:FALSE" \
  "authorityKeyIdentifier = keyid" > client.ext
for name in client client-other; do
  subject=$client_subject
  [ "$name" = client-other ] && subject="/CN=crystal-mysql other client"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "$subject" -keyout "$name.key" -out "$name.csr" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA client-ca.pem -CAkey client-ca.key -CAcreateserial \
    -days 30 -extfile client.ext -out "$name.pem" 2>/dev/null
done
# The X509 server checks client certificates against both CAs.
cat ca.pem client-ca.pem > ca-bundle.pem
# The server reads its key as the mysql user inside the container.
chmod 644 ca.pem server.pem server.key ca-bundle.pem

docker rm -f crystal-mysql-tls crystal-mysql-tls12 crystal-mysql-x509 >/dev/null 2>&1 || true
common=(-e MYSQL_ALLOW_EMPTY_PASSWORD=yes -v "$PWD:/certs:ro")
tls_args=(--ssl-ca=/certs/ca.pem --ssl-cert=/certs/server.pem --ssl-key=/certs/server.key)
docker run -d --name crystal-mysql-tls -p 127.0.0.1:3306:3306 "${common[@]}" "$image" \
  "${tls_args[@]}" --tls-version=TLSv1.2,TLSv1.3 >/dev/null
docker run -d --name crystal-mysql-tls12 -p 127.0.0.1:3312:3306 "${common[@]}" "$image" \
  "${tls_args[@]}" --tls-version=TLSv1.2 >/dev/null
docker run -d --name crystal-mysql-x509 -p 127.0.0.1:3313:3306 "${common[@]}" "$image" \
  --ssl-ca=/certs/ca-bundle.pem --ssl-cert=/certs/server.pem --ssl-key=/certs/server.key \
  --tls-version=TLSv1.3 --require-secure-transport=ON >/dev/null

for name in crystal-mysql-tls crystal-mysql-tls12 crystal-mysql-x509; do
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
echo "MYSQL_X509_HOST=127.0.0.1:3313"
echo "MYSQL_X509_CLIENT_CERT=$PWD/client.pem"
echo "MYSQL_X509_CLIENT_KEY=$PWD/client.key"
echo "MYSQL_X509_OTHER_CLIENT_CERT=$PWD/client-other.pem"
echo "MYSQL_X509_OTHER_CLIENT_KEY=$PWD/client-other.key"
echo "MYSQL_X509_CLIENT_SUBJECT=$client_subject"
echo "MYSQL_X509_CLIENT_ISSUER=$client_ca_subject"
