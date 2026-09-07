#!/bin/bash

## Test that IP address certificates don't force Let's Encrypt's `shortlived`
## profile on CAs that don't offer it.
##
## Google Trust Services issues IP address certificates under its own default
## profile and only knows about the `standard` and `minimal` profiles, so
## requesting `shortlived` there would fail. That path can't be exercised
## against GTS in CI (it needs EAB credentials and a publicly routable IP), so
## we reproduce it with Pebble: `ACME_IP_CERT_PROFILE=none` takes the same
## branch, and Pebble's default profile has a distinctly different validity
## period than its `shortlived` one. The renewal threshold must follow the
## profile too: a long lived certificate keeps the regular ACME_RENEW_AFTER
## default instead of the 3 days meant for short lived ones.
##
## See docs/IP-address-certificates.md and docs/Google-Trust-Services.md.

target_ip='10.30.50.1'
pebble_default_profile_validity=157766400
validity_tolerance=2

if [[ -z ${GITHUB_ACTIONS} ]]; then
  le_container_name="$(basename "${0%/*}")_$(date "+%Y-%m-%d_%H.%M.%S")"
else
  le_container_name="$(basename "${0%/*}")"
fi
run_le_container "${1:?}" "${le_container_name}"   --cli-args "--env ACME_IP_CERT_PROFILE=none"

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

run_nginx_container --hosts "${target_ip}"

if ! wait_for_symlink "${target_ip}" "${le_container_name}" "./${target_ip}/fullchain.pem"; then
  echo "Failed to issue a certificate for IP address ${target_ip} without a certificate profile."
fi

issue_debug_log="$(docker logs "${le_container_name}" 2>&1 | grep 'Calling acme.sh --issue' | tail -1)"
if [[ "${issue_debug_log}" == *'--cert-profile'* ]]; then
  echo "acme.sh was called with a certificate profile although the CA doesn't require one for IP address certificates: ${issue_debug_log}"
elif [[ "${DRY_RUN:-}" == 1 ]]; then
  echo "acme.sh was called without --cert-profile for the IP address certificate."
fi

if [[ "${issue_debug_log}" != *'--days 60'* ]]; then
  echo "acme.sh was not called with the regular renewal threshold (--days 60) for a certificate that isn't short lived: ${issue_debug_log}"
elif [[ "${DRY_RUN:-}" == 1 ]]; then
  echo "acme.sh was called with the regular renewal threshold (--days 60)."
fi

actual_validity="$(get_cert_validity_seconds "${target_ip}" "${le_container_name}")"
validity_diff="$((actual_validity - pebble_default_profile_validity))"
if (( validity_diff < 0 )); then
  validity_diff=$(( -validity_diff ))
fi
if (( validity_diff > validity_tolerance )); then
  echo "IP address certificate validity is ${actual_validity} seconds instead of the expected ${pebble_default_profile_validity} (CA default profile) +/- ${validity_tolerance}."
elif [[ "${DRY_RUN:-}" == 1 ]]; then
  echo "IP address certificate validity matches the CA default profile (${pebble_default_profile_validity} seconds)."
fi
