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

declare -A expect_ip_profile=(
  ['https://acme-v02.api.letsencrypt.org/directory']='shortlived'
  ['https://acme-staging-v02.api.letsencrypt.org/directory']='shortlived'
  ['https://pebble:14000/dir']='shortlived'
  ['https://dv.acme-v02.api.pki.goog/directory']=''
  ['https://dv-sxg.acme-v02.api.pki.goog/directory']=''
  ['https://acme.zerossl.com/v2/DV90']=''
)

for ca_uri in "${!expect_ip_profile[@]}"; do
  actual_profile="$(ca_default_ip_cert_profile "${ca_uri}")"
  expected_profile="${expect_ip_profile[${ca_uri}]}"
  if [[ "${actual_profile}" != "${expected_profile}" ]]; then
    echo "ca_default_ip_cert_profile '${ca_uri}' returned '${actual_profile}', expected '${expected_profile}'."
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
elif [[ "${ipdns_output}" != *"DNS-01 is not supported for IP identifiers"* ]]; then
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

## Check the acme.sh --issue parameters update_cert() builds for IP address
## certificates, against a CA that requires the shortlived profile for them
## (Let's Encrypt) and one that doesn't offer that profile at all (Google
## Trust Services). Neither CA is reachable from the test suite, so acme.sh
## is replaced by a stub recording how it was called: a bash function shadows
## the real command without any PATH juggling.
function acme.sh {
  echo "${*}" >> /tmp/acme_calls
  return 0
}

accountemail='test@example.com'
DEFAULT_EMAIL="${accountemail}"
# Pre-create the ACME accounts so update_cert() gets past registration.
for ca_host_dir in 'acme-v02.api.letsencrypt.org' 'dv.acme-v02.api.pki.goog'; do
  mkdir -p "/etc/acme.sh/${accountemail}/ca/${ca_host_dir}/directory"
  echo "{\"contact\":[\"mailto:${accountemail}\"]}"     > "/etc/acme.sh/${accountemail}/ca/${ca_host_dir}/directory/account.json"
done

function issue_params {
  # Echo the parameters of the acme.sh --issue call made for container $1.
  : > /tmp/acme_calls
  update_cert "${1:?}" &> /dev/null
  grep '^--issue ' /tmp/acme_calls | tail -1
}

ACME_leip_HOST=('203.0.113.42')
ACME_leip_CA_URI='https://acme-v02.api.letsencrypt.org/directory'
leip_params="$(issue_params leip)"
if [[ -z "${leip_params}" ]]; then
  echo "update_cert did not call acme.sh --issue for a Let's Encrypt IP address certificate."
else
  if [[ "${leip_params}" != *'--cert-profile shortlived'* ]]; then
    echo "The Let's Encrypt IP address certificate was not requested with the shortlived profile: ${leip_params}"
  fi
  if [[ "${leip_params}" != *'--days 3'* ]]; then
    echo "The Let's Encrypt IP address certificate was not requested with the short lived renewal threshold (--days 3): ${leip_params}"
  fi
fi

ACME_gtsip_HOST=('203.0.113.42')
ACME_gtsip_CA_URI='https://dv.acme-v02.api.pki.goog/directory'
gtsip_params="$(issue_params gtsip)"
if [[ -z "${gtsip_params}" ]]; then
  echo "update_cert did not call acme.sh --issue for a Google Trust Services IP address certificate."
else
  if [[ "${gtsip_params}" == *'--cert-profile'* ]]; then
    echo "The Google Trust Services IP address certificate was requested with a certificate profile, but GTS only offers standard and minimal: ${gtsip_params}"
  fi
  if [[ "${gtsip_params}" != *'--days 60'* ]]; then
    echo "The Google Trust Services IP address certificate was not requested with the regular renewal threshold (--days 60): ${gtsip_params}"
  fi
fi

ACME_gtsipminimal_HOST=('203.0.113.42')
ACME_gtsipminimal_CA_URI='https://dv.acme-v02.api.pki.goog/directory'
ACME_gtsipminimal_CERT_PROFILE='minimal'
gtsipminimal_params="$(issue_params gtsipminimal)"
if [[ "${gtsipminimal_params}" != *'--cert-profile minimal'* ]]; then
  echo "An explicit certificate profile was not honored for a Google Trust Services IP address certificate: ${gtsipminimal_params}"
fi

ACME_ipnone_HOST=('203.0.113.42')
ACME_ipnone_CA_URI='https://acme-v02.api.letsencrypt.org/directory'
ACME_IP_CERT_PROFILE='none'
ipnone_params="$(issue_params ipnone)"
if [[ "${ipnone_params}" == *'--cert-profile'* ]]; then
  echo "ACME_IP_CERT_PROFILE=none did not prevent the automatic IP certificate profile: ${ipnone_params}"
fi
unset ACME_IP_CERT_PROFILE
EOF
)"

docker run --rm "$1" bash -c "${commands}" 2>&1
