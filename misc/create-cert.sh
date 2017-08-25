#!/bin/sh

# This script creates a certificate for a domain.
#
# Source: https://datacenteroverlords.com/2012/03/01/creating-your-own-ssl-certificate-authority/

domain="$1"
ca_name="My Certificate Authority"

if [ -z "domain" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

if [ $(echo "domain" | grep -c '.p2p$') -ne 0 ]; then
  echo "*.p2p TLD only used for domain filtering. It is not meant to be part of the domain."
  exit 1
fi


# Reuse root certificate if present
if [ ! -f rootCA.key ]; then
  echo "Create root certificate"
  openssl genrsa -out rootCA.key 2048

  echo "Create self signed certificate"
  openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem -subj "/CN=${ca_name}"
fi

echo "Create normal certificate"
openssl genrsa -out ${domain}.key 2048

echo "Create signing request"
openssl req -new -key ${domain}.key -out ${domain}.csr -subj "/CN=${domain}"

echo "Create signed certificate"
openssl x509 -req -in ${domain}.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out ${domain}.crt -days 500 -sha256

# Cleanup
rm ${domain}.csr
rm rootCA.srl

exit 0
