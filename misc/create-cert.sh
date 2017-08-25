#!/bin/sh

# This script creates a certificate for a domain.
#
# Source: https://datacenteroverlords.com/2012/03/01/creating-your-own-ssl-certificate-authority/


while [ -z "$DOMAIN" ]; do
	echo -n "Enter domain: "
	read DOMAIN
done

# Reuse root certificate if present
if [ ! -f rootCA.key ]; then
  echo "Create root certificate"
  openssl genrsa -out rootCA.key 2048

  echo "Create self signed certificate"
  openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem

  rm rootCA.srl
fi

echo "Create normal certificate"
openssl genrsa -out device.key 2048

echo "Create signing request"
openssl req -new -key device.key -out device.csr -subj "/CN=$DOMAIN"

echo "Create signed certificate"
openssl x509 -req -in device.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out device.crt -days 500 -sha256

# Cleanup
rm device.csr
