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
EOF
)"

docker run --rm "$1" bash -c "${commands}" 2>&1
