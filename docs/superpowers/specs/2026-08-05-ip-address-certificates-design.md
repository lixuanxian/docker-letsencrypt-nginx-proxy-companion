# IP Address Certificates — Design

## Background

Let's Encrypt now issues publicly trusted certificates for IP addresses (announced
2025-01-16, first cert issued 2025-07-01, GA 2026-01-15). These certificates have
hard restrictions that differ from ordinary domain certificates:

- Validation is restricted to **HTTP-01 or TLS-ALPN-01**. DNS-01 is not available
  (there is no DNS to validate an IP against).
- Wildcards are not applicable (an IP can't be a wildcard).
- Issuance automatically selects the **`shortlived`** certificate profile, valid for
  ~160 hours (~6.7 days) instead of the usual 90 days.
- No public documentation confirms whether a single certificate may mix IP and DNS
  name SANs; the safe assumption is that it can't.

Sources: [Announcing Six Day and IP Address Certificate Options](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs),
[6-day and IP Address Certificates are Generally Available](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability).

## Current state of this repository

Investigation of `app/letsencrypt_service.sh`, `app/functions.sh`, and
`app/letsencrypt_service_data.tmpl` found:

- No code anywhere validates the shape of a host string. An IP literal already
  flows unmodified from `ACME_HOST`/`LETSENCRYPT_HOST` through docker-gen's
  template into the bash arrays `letsencrypt_service.sh` consumes.
- The vendored `acme.sh` (3.1.4) already accepts `-d <IP>` and `--cert-profile
  shortlived` with no special handling required on its side.
- The repository already has two generic knobs that map straight onto what IP
  certificates need: `ACME_CERT_PROFILE` → `--cert-profile`, and
  `ACME_RENEW_AFTER` → `--days`. Nothing currently sets sensible defaults for
  either when the host is an IP.
- HTTP-01 challenge handling (`add_location_configuration`,
  `add_standalone_configuration` in `functions.sh`) matches host strings
  literally, falling back to wildcard-location lookups that split on `.`. For
  an IP host this fallback is a no-op (IPv6 has no dots; IPv4's dots never
  form a matching `*.x.y` wildcard file) and falls through to the `default`
  location — this path needs no code change, only verification.
- Certificate directories and symlinks
  (`relative_certificate_dir`/`create_links` in `letsencrypt_service.sh`) use
  the host literal directly as a filename component. IPv6 literals contain
  `:`, which is a legal filename character on Linux — expected to work
  as-is, to be confirmed in testing.
- The test suite's pinned Pebble instance (`test/setup/pebble/`, version
  2.10.1) already defines a `shortlived` profile (518400s ≈ 6 days) and it's
  exercised by the existing `cert_profiles` test — but always against DNS
  names, never an IP identifier. Whether this Pebble version implements IP
  identifiers (`draft-ietf-acme-ip`) is unconfirmed and must be checked during
  implementation.

## Goals

Make requesting a certificate for a public IP address (`ACME_HOST=<IP>`) a
first-class, documented, tested path — with automatic, sensible defaults, and
clear errors for the combinations Let's Encrypt does not support — rather than
something that happens to work if a user manually wires up
`ACME_CERT_PROFILE`/`ACME_RENEW_AFTER` correctly today.

Out of scope: TLS-ALPN-01 support (not implemented for domains either, and not
required since HTTP-01 already covers IP certs), changes to the companion
`nginx-proxy` repository (out of tree), pre-validating that an IP is publicly
routable (left to the CA).

## Design

### 1. IP detection helpers (`app/functions.sh`)

Two new heuristic (not RFC-strict) helpers:

```bash
function is_ipv4_address {
    local -r host="${1?missing host argument}"
    [[ "${host}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    local octet
    for octet in ${host//./ }; do
        (( octet <= 255 )) || return 1
    done
}

function is_ip_address {
    local -r host="${1?missing host argument}"
    is_ipv4_address "${host}" && return 0
    # IPv6 literals are the only host values containing ':' — DNS labels
    # can't. A permissive character-class check is sufficient here; anything
    # that isn't actually a valid IPv6 address will be rejected later by
    # acme.sh/the ACME server anyway.
    [[ "${host}" == *:* && "${host}" =~ ^[0-9A-Fa-f:]+$ ]]
}
```

These are classification helpers used to pick defaults and validate
combinations — they are deliberately not a full IP-address parser. Getting a
false negative (an exotic literal not recognized as an IP) just means the
smart defaults don't kick in and the user has to set
`ACME_CERT_PROFILE`/`ACME_RENEW_AFTER_IP` by hand, same as today. A false
positive is not realistically possible since DNS labels cannot contain `:`
and `is_ipv4_address` requires exactly 4 dot-separated numeric octets.

### 2. Classifying a certificate's hosts (`app/letsencrypt_service.sh`, `update_cert`)

Right after `hosts_array` is resolved, classify every entry:

```bash
local -a ip_hosts=() dns_hosts=()
for host in "${hosts_array[@]}"; do
    if is_ip_address "${host}"; then
        ip_hosts+=("${host}")
    else
        dns_hosts+=("${host}")
    fi
done
local ip_certificate='false'
if [[ ${#ip_hosts[@]} -gt 0 ]]; then
    ip_certificate='true'
fi
```

Rules, checked before any acme.sh invocation is built:

- **Mixed IP + DNS names in the same cert** (`${#ip_hosts[@]} > 0` and
  `${#dns_hosts[@]} > 0`): error out immediately —
  `"Error: cannot mix IP addresses (…) and domain names (…) in the same certificate (${base_domain}). Split them with ACME_SINGLE_DOMAIN_CERTS=true."`
  `return 1`, same pattern as the existing wildcard/HTTP-01 rejection.
- **IP certificate + `DNS-01` challenge**: error out —
  `"Error: IP address certificates (${base_domain}) require the HTTP-01 or TLS-ALPN-01 challenge; DNS-01 is not supported by Let's Encrypt for IP identifiers."`
  `return 1`. (TLS-ALPN-01 isn't implemented by this project at all — it
  already falls into the pre-existing "unknown ACME challenge method" branch,
  no new handling needed.)

### 3. Smart defaults for IP certificates

Two independent defaults, both **only applied when the value wasn't already
set** (per-container override always wins; this mirrors the existing
precedence pattern used for `ACME_CERT_PROFILE`/`ACME_RENEW_AFTER`):

**Cert profile** (`update_cert`, near the existing `ACME_CERT_PROFILE`
handling around line 466): if `ip_certificate == true` and neither the
per-container nor the global `ACME_CERT_PROFILE` is set, default to
`shortlived`:

```bash
local -n acme_cert_profile="ACME_${cid}_CERT_PROFILE"
if [[ -n "${acme_cert_profile}" ]]; then
    params_issue_arr+=(--cert-profile "${acme_cert_profile}")
elif [[ -n ${ACME_CERT_PROFILE// } ]]; then
    params_issue_arr+=(--cert-profile "${ACME_CERT_PROFILE}")
elif [[ "${ip_certificate}" == 'true' ]]; then
    params_issue_arr+=(--cert-profile shortlived)
fi
```

**Renewal threshold**: a *new* global env var `ACME_RENEW_AFTER_IP` (default
`3`, i.e. renew 3 days after issuance — comfortably inside the ~6.7-day
validity window with buffer for retries) is introduced instead of overloading
`ACME_RENEW_AFTER`. Reason: `ACME_RENEW_AFTER` is defaulted at the top of the
script (`ACME_RENEW_AFTER="${ACME_RENEW_AFTER:-60}"`) before per-container
resolution happens, so by the time `update_cert` runs there is no way to tell
"user explicitly exported 60" apart from "nobody set it, this is the
fallback" — silently repurposing that value for IP certs would risk
overriding a value the user actually meant for their domain certs. A
dedicated variable removes the ambiguity entirely and gives users an explicit
documented knob:

```bash
ACME_RENEW_AFTER_IP="${ACME_RENEW_AFTER_IP:-3}"
# ...
local -n renew_after="ACME_${cid}_RENEW_AFTER"
if [[ -z "${renew_after}" ]] || [[ ! "${renew_after}" =~ ^[0-9]+$ ]]; then
    if [[ "${ip_certificate}" == 'true' ]]; then
        renew_after="${ACME_RENEW_AFTER_IP}"
    else
        renew_after="${ACME_RENEW_AFTER}"
    fi
fi
```

No template changes are required for this — `ACME_{cid}_RENEW_AFTER` is
already threaded through per-container from `letsencrypt_service_data.tmpl`;
`ACME_RENEW_AFTER_IP` is a companion-container-level global env var read
directly by `letsencrypt_service.sh`, exactly like `ACME_RENEW_AFTER` and
`CERTS_UPDATE_INTERVAL` are today.

### 4. HTTP-01 challenge path

No code changes expected. `add_location_configuration` and
`add_standalone_configuration` already treat the host as an opaque string;
their wildcard-location fallback (`ascending_wildcard_locations`/
`descending_wildcard_locations`, which split on `.`) degrades to a no-op for
IP literals and falls through to the `default` vhost/location file. This will
be exercised directly by the new test (§7) rather than asserted purely by
reading the code.

### 5. Certificate storage (directories and symlinks)

`relative_certificate_dir="${base_domain}"` and `create_links` build paths
like `/etc/nginx/certs/${base_domain}/cert.pem` and
`/etc/nginx/certs/${domain}.crt`. For an IPv6 host such as `2001:db8::1` this
produces a directory/symlink name containing `:`, which is a legal character
in a Linux filename (only `/` and NUL are forbidden) and requires no
`mkdir`/`ln` changes. This will be verified end-to-end by the new test rather
than assumed; if testing surfaces a real problem (e.g. some other tool in the
chain choking on the colon) it will be fixed as part of implementation, but
no defensive workaround is being designed preemptively for a problem that
hasn't been observed.

### 6. Documentation

New `docs/IP-address-certificates.md`, following the structure of the
existing `docs/Standalone-certificates.md`:

- What Let's Encrypt supports and requires for IP certs (profile, validity,
  challenge types, no wildcards) with a link to the official announcement.
- What this project supports: HTTP-01 only (no TLS-ALPN-01), IPv4 and IPv6.
- How to request one: set `ACME_HOST`/`LETSENCRYPT_HOST` on a container to a
  public IP, same as a domain; the `shortlived` profile and a 3-day renewal
  threshold are applied automatically.
- The `ACME_RENEW_AFTER_IP` variable (default, how/when to override it).
- The "no mixing IP and domain names in one certificate" and "no DNS-01 for
  IP certs" restrictions, with the exact error messages so they're
  greppable.
- A minimal `docker-compose.yml` snippet.

Cross-links added from `README.md`'s documentation list and from the
"Certificate profile" / "Certificate renewal timing" sections of
`docs/Let's-Encrypt-and-ACME.md`.

### 7. Testing

- **Feasibility check first**: before writing the full integration test,
  confirm empirically whether the pinned Pebble 2.10.1 issues certificates
  for an IP identifier at all (a manual `acme.sh --issue -d 127.0.0.1
  --server <pebble> --cert-profile shortlived` style run against the local
  Pebble compose stack). This determines which of the next two bullets
  happens.
- **If Pebble supports IP identifiers**: add `test/tests/certs_ip/run.sh`
  following the `cert_profiles`/`certs_standalone` pattern — request a
  certificate for an IP (Pebble's challtestsrv is already reachable at a
  fixed IP on the `acme_net` docker network, `10.30.50.3`, which is usable as
  the test subject), assert the profile defaulted to `shortlived`
  (~518400s validity, reusing `get_cert_validity_seconds` like
  `cert_profiles` does), and assert the symlink/cert files exist under the
  literal IP name. Register it in `test/config.sh` alongside the other
  Pebble-gated tests.
- **If Pebble does not support IP identifiers**: skip the end-to-end
  issuance test, document why in the PR description and in
  `docs/IP-address-certificates.md` ("automated coverage pending Pebble
  support for RFC IP identifiers; verified manually against Let's Encrypt
  staging"), and record the manual verification steps taken.
- **Validation-only test** (works regardless of Pebble's IP support, no real
  ACME server involved): a new test that sources `functions.sh` /
  `letsencrypt_service.sh` inside a throwaway container (same style as
  `test/tests/standalone_ipv6/run.sh`, which calls functions directly rather
  than running the full service) and asserts:
  - `is_ip_address` correctly classifies representative IPv4, IPv6, and
    domain strings.
  - `update_cert` rejects a mixed IP+domain host list with the documented
    error message.
  - `update_cert` rejects `ACME_CHALLENGE=DNS-01` combined with an IP host
    with the documented error message.

## Error handling summary

| Condition | Behavior |
|---|---|
| IP host, no challenge override | HTTP-01 (existing default), works unchanged |
| IP host, `ACME_CHALLENGE=HTTP-01` explicit | Works unchanged |
| IP host, `ACME_CHALLENGE=DNS-01` | Hard error, cert skipped, service loop continues with other certs |
| IP + domain mixed in one `ACME_HOST` | Hard error, cert skipped, service loop continues with other certs |
| IP host, no `ACME_CERT_PROFILE` set | Defaults to `shortlived` |
| IP host, no `ACME_RENEW_AFTER` set on that container | Defaults to `ACME_RENEW_AFTER_IP` (3) |
| IP host, explicit `ACME_CERT_PROFILE`/`ACME_RENEW_AFTER` | User's value always wins |

Errors follow the existing convention in this file: `echo "Error: ..."` to
stdout/stderr as appropriate and `return 1` from `update_cert`, which the
caller (`update_certs`) already treats as "skip this one, keep processing the
rest" — no new error-handling plumbing needed.

## Testing the design itself

This spec's claims about `add_location_configuration`,
`ascending_wildcard_locations`/`descending_wildcard_locations`, and the
symlink/directory naming are based on reading the current code, not on
having run it with IP inputs yet. The implementation plan must verify these
claims against a running container before relying on "no code change
needed" for §4 and §5.
