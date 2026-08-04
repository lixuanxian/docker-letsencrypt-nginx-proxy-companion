#!/bin/bash

## Test for the is_ip_address / is_ipv4_address classification helpers used
## to detect IP address certificates, and for the update_cert() validation
## rules and symlink handling built on top of them. See
## docs/IP-address-certificates.md.

commands="$(cat <<'EOF'
source /app/functions.sh

declare -A expect_ip=(
  ['203.0.113.42']=0
  ['10.0.0.1']=0
  ['255.255.255.255']=0
  ['2001:db8::1']=0
  ['::1']=0
  ['fe80::1']=0
  ['fe80::1%eth0']=1
  ['example.com']=1
  ['sub.example.com']=1
  ['203.0.113.42.example.com']=1
  ['300.1.1.1']=1
  ['not-an-ip']=1
)

for host in "${!expect_ip[@]}"; do
  is_ip_address "${host}"
  actual=$?
  expected="${expect_ip[${host}]}"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "is_ip_address '${host}' returned ${actual}, expected ${expected}."
  fi
done

source /app/letsencrypt_service.sh --source-only

ACME_mixed_HOST=('203.0.113.42' 'example.com')
ACME_mixed_CHALLENGE=''
mixed_output="$(update_cert mixed 2>&1)"
mixed_rc=$?
if [[ ${mixed_rc} -eq 0 ]]; then
  echo "update_cert accepted a certificate mixing an IP address and a domain name, it should have rejected it."
elif [[ "${mixed_output}" != *"cannot mix IP addresses and domain names"* ]]; then
  echo "update_cert rejected the mixed IP/domain certificate for the wrong reason: ${mixed_output}"
fi

ACME_ipdns_HOST=('203.0.113.42')
ACME_ipdns_CHALLENGE='DNS-01'
ipdns_output="$(update_cert ipdns 2>&1)"
ipdns_rc=$?
if [[ ${ipdns_rc} -eq 0 ]]; then
  echo "update_cert accepted a DNS-01 challenge for an IP address certificate, it should have rejected it."
elif [[ "${ipdns_output}" != *"DNS-01 is not supported by Let's Encrypt for IP identifiers"* ]]; then
  echo "update_cert rejected the IP+DNS-01 certificate for the wrong reason: ${ipdns_output}"
fi

mkdir -p '/etc/nginx/certs/2001:db8::1'
echo 'dummy-fullchain' > '/etc/nginx/certs/2001:db8::1/fullchain.pem'
echo 'dummy-key' > '/etc/nginx/certs/2001:db8::1/key.pem'
create_links '2001:db8::1' '2001:db8::1'

if [[ ! -L '/etc/nginx/certs/2001:db8::1.crt' ]]; then
  echo "create_links did not create a certificate symlink for the IPv6 host 2001:db8::1."
fi
if [[ ! -L '/etc/nginx/certs/2001:db8::1.key' ]]; then
  echo "create_links did not create a private key symlink for the IPv6 host 2001:db8::1."
fi

crt_target="$(readlink '/etc/nginx/certs/2001:db8::1.crt')"
if [[ "${crt_target}" != './2001:db8::1/fullchain.pem' ]]; then
  echo "The certificate symlink for the IPv6 host 2001:db8::1 points to ${crt_target} instead of ./2001:db8::1/fullchain.pem."
fi

crt_content="$(cat '/etc/nginx/certs/2001:db8::1.crt')"
if [[ "${crt_content}" != 'dummy-fullchain' ]]; then
  echo "The certificate symlink for the IPv6 host 2001:db8::1 does not resolve to the expected file content."
fi
EOF
)"

docker run --rm "$1" bash -c "${commands}" 2>&1
