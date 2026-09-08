#!/bin/bash

## Test for IP address certificates (Let's Encrypt IP identifiers, GA since 2026-01-15).
## See docs/IP-address-certificates.md.

## The acme_net docker network's gateway address (10.30.50.1) is already the
## address every domain-based test in this suite validates against:
## test/setup/pebble/setup-pebble.sh points pebble-challtestsrv's default A
## answer at it, which Docker's NAT then forwards to nginx-proxy's published
## port 80. For an IP-identifier certificate the ACME client connects
## directly to the identifier with no DNS lookup involved, so requesting a
## certificate for that same address exercises the exact same route with no
## extra network setup needed.
target_ip='10.30.50.1'
ip_shortlived_profile_validity=518400
validity_tolerance=2

if [[ -z ${GITHUB_ACTIONS} ]]; then
  le_container_name="$(basename "${0%/*}")_$(date "+%Y-%m-%d_%H.%M.%S")"
else
  le_container_name="$(basename "${0%/*}")"
fi
run_le_container "${1:?}" "${le_container_name}"

# Cleanup function with EXIT trap
function cleanup {
  # Remove the Nginx container silently.
  docker rm --force "${target_ip}" &> /dev/null
  # Cleanup the files created by this run of the test to avoid foiling following test(s).
  docker exec "${le_container_name}" cleanup_test_artifacts
  # Stop the LE container
  docker stop "${le_container_name}" > /dev/null
}
trap cleanup EXIT

# Request a certificate for the IP address, letting the smart defaults pick
# the shortlived profile and the short IP renewal threshold automatically.
run_nginx_container --hosts "${target_ip}"

if ! wait_for_symlink "${target_ip}" "${le_container_name}" "./${target_ip}/fullchain.pem"; then
  echo "Failed to issue a certificate for IP address ${target_ip}."
fi

created_cert="$(docker exec "${le_container_name}" \
  openssl x509 -in "/etc/nginx/certs/${target_ip}/cert.pem" -text -noout)"

if ! grep -q "IP Address:${target_ip}" <<< "${created_cert}"; then
  echo "IP address ${target_ip} did not appear as a SAN on the certificate."
elif [[ "${DRY_RUN:-}" == 1 ]]; then
  echo "IP address ${target_ip} is on the certificate as a SAN."
fi

actual_validity="$(get_cert_validity_seconds "${target_ip}" "${le_container_name}")"
validity_diff="$((actual_validity - ip_shortlived_profile_validity))"
if (( validity_diff < 0 )); then
  validity_diff=$(( -validity_diff ))
fi
if (( validity_diff > validity_tolerance )); then
  echo "IP address certificate validity is ${actual_validity} seconds instead of the expected ${ip_shortlived_profile_validity} (shortlived profile) +/- ${validity_tolerance}."
elif [[ "${DRY_RUN:-}" == 1 ]]; then
  echo "IP address certificate validity matches the shortlived profile (${ip_shortlived_profile_validity} seconds)."
fi

issue_debug_log="$(docker logs "${le_container_name}" 2>&1 | grep 'Calling acme.sh --issue' | tail -1)"
if [[ "${issue_debug_log}" != *'--cert-profile shortlived'* ]]; then
  echo "acme.sh was not called with --cert-profile shortlived for the IP address certificate: ${issue_debug_log}"
fi
if [[ "${issue_debug_log}" != *'--days 3'* ]]; then
  echo "acme.sh was not called with the default IP renewal threshold (--days 3): ${issue_debug_log}"
fi

created_cert_fingerprint="$(docker exec "${le_container_name}" \
  openssl x509 -in "/etc/nginx/certs/${target_ip}/cert.pem" -fingerprint -noout)"
if ! wait_for_conn --domain "${target_ip}" --cert-match "${created_cert_fingerprint}"; then
  echo "Nginx served an incorrect certificate for IP address ${target_ip}."
elif [[ "${DRY_RUN:-}" == 1 ]]; then
  echo "The correct certificate for IP address ${target_ip} was served by Nginx."
fi
