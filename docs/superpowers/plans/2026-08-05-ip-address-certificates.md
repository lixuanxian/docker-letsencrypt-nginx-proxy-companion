# IP Address Certificates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make requesting a Let's Encrypt certificate for a public IP address (`ACME_HOST=<IP>`) a first-class, validated, documented, tested path in acme-companion.

**Architecture:** All new logic lives in the existing bash scripts (`app/functions.sh`, `app/letsencrypt_service.sh`) that already build every `acme.sh` invocation — no new files, no changes to the docker-gen template (`app/letsencrypt_service_data.tmpl`) or to the vendored `acme.sh`. Two new heuristic classifier functions decide, per certificate, whether its hosts are IP addresses; that classification then drives (a) two new hard-error validations and (b) two new automatic defaults, all inside the existing `update_cert()` function.

**Tech Stack:** bash (project's existing style: 4-space indent, `local -r`/`local -n` namerefs, `function name {}` declarations), Docker/Docker Compose for the test harness, Pebble (local ACME test server, pinned at v2.10.1) for integration tests, shellcheck for linting.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-05-ip-address-certificates-design.md` — every task below implements one section of it; read it first if anything here is ambiguous.
- No changes to `app/letsencrypt_service_data.tmpl` or the vendored `acme.sh` (pinned `ACMESH_VERSION=3.1.4` in `Dockerfile`).
- New global env var: `ACME_RENEW_AFTER_IP` (default `3`), independent from `ACME_RENEW_AFTER` (default `60`) — see spec §3 for why they must stay separate.
- TLS-ALPN-01 is out of scope (not implemented for domains either); only HTTP-01 needs to keep working for IP certs.
- All bash additions must pass `shellcheck` using this repo's `.shellcheckrc` (run via `docker run --rm -v "$PWD":/mnt -w /mnt koalaman/shellcheck:stable <files>`, since shellcheck isn't installed locally).
- Test style: follow existing files under `test/tests/*/run.sh` exactly — `run_le_container`/`run_nginx_container`/`wait_for_symlink`/`get_cert_validity_seconds`/etc. from `test/tests/test-functions.sh`, `trap cleanup EXIT`, and "no output on stdout = test passed" (only `echo` when something is wrong, unless the test dir has its own `expected-std-out.txt`).
- Local test run entrypoint once Task 7 is reached: `ACME_CA=pebble PEBBLE_CONFIG=pebble-config.json <repo>/test/run.sh -t <test-name> <built-image>` (exact invocation confirmed in Task 7 from `.github/workflows/test.yml`).

---

### Task 1: IP address classification helpers

**Files:**
- Modify: `app/functions.sh` (insert after the `parse_true` function, which ends at line 25, before the `VHOST_DIR` declaration at line 27)
- Create: `test/tests/certs_ip_validation/run.sh`
- Modify: `test/config.sh` (add `certs_ip_validation` to `globalTests`)

**Interfaces:**
- Produces: `is_ipv4_address(host) -> exit 0 if host is a dotted-quad IPv4 literal with each octet <= 255, else exit 1`. `is_ip_address(host) -> exit 0 if host is an IPv4 literal (via is_ipv4_address) or looks like an IPv6 literal (contains ':' and only hex digits/colons), else exit 1`. Both are consumed by Task 2 and Task 4.

- [ ] **Step 1: Write the failing test**

Create `test/tests/certs_ip_validation/run.sh`:

```bash
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
```

Make it executable and register it so the test runner picks it up. In
`test/config.sh`, add `certs_ip_validation` to the `globalTests` array
(alongside `standalone_ipv6`, since this test needs no live ACME server and
should run unconditionally):

```bash
globalTests+=(
	docker_api
	docker_api_legacy
	docker_api_tls
	location_config
	debug_acmesh_log
	certs_single
	certs_san
	certs_single_domain
	certs_standalone
	standalone_ipv6
	certs_ip_validation
	force_renew
	acme_accounts
	private_keys
	renew_private_keys
	container_restart
	permissions_default
	permissions_custom
	symlinks
	acme_hooks
	certs_renew_after
	certs_default_renew_deprecated
	ocsp_must_staple
	certs_persistence
)
```

- [ ] **Step 2: Run test to verify it fails**

The project's built image is required to run this. Build it and run the new
test in isolation:

```bash
chmod +x test/tests/certs_ip_validation/run.sh
docker build -t acme-companion:dev .
docker run --rm acme-companion:dev bash -c "source /app/functions.sh" 2>&1
./test/tests/certs_ip_validation/run.sh acme-companion:dev
```

Expected: the last command errors with `is_ip_address: command not found`
(or similar), since `is_ip_address`/`is_ipv4_address` don't exist yet.

- [ ] **Step 3: Write minimal implementation**

In `app/functions.sh`, insert this block right after the `parse_true`
function (after its closing `}` on line 25) and before the `VHOST_DIR`
declaration on line 27:

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
	# Heuristic classifier used to select IP-certificate defaults, not a
	# strict RFC validator: a false negative just means the automatic
	# defaults (see letsencrypt_service.sh) don't kick in and the value is
	# treated like a regular hostname. A false positive can't happen for a
	# real domain name, since DNS labels never contain ':' and the IPv4
	# check above requires exactly 4 dot-separated numeric octets. IPv6
	# zone indices (e.g. fe80::1%eth0) are intentionally not recognized:
	# link-local addresses aren't publicly routable and Let's Encrypt
	# wouldn't issue a certificate for one anyway.
	local -r host="${1?missing host argument}"
	is_ipv4_address "${host}" && return 0
	[[ "${host}" == *:* && "${host}" =~ ^[0-9A-Fa-f:]+$ ]]
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
docker build -t acme-companion:dev .
./test/tests/certs_ip_validation/run.sh acme-companion:dev
```

Expected: no output (all 12 classifications match).

- [ ] **Step 5: Commit**

```bash
git add app/functions.sh test/tests/certs_ip_validation/run.sh test/config.sh
git commit -m "feat: add is_ip_address/is_ipv4_address classification helpers"
```

---

### Task 2: Reject unsupported host combinations in update_cert()

**Files:**
- Modify: `app/letsencrypt_service.sh:164-220` (see exact anchors below)
- Modify: `test/tests/certs_ip_validation/run.sh` (extend, same file as Task 1)

**Interfaces:**
- Consumes: `is_ip_address(host)` from Task 1.
- Produces: `update_cert()` now returns 1 with a message containing
  `"cannot mix IP addresses and domain names"` when a certificate's host list
  mixes IPs and domain names, and returns 1 with a message containing
  `"DNS-01 is not supported by Let's Encrypt for IP identifiers"` when an
  IP-only certificate requests the `DNS-01` challenge. Also produces the
  local variable `ip_certificate` (`'true'`/`'false'`), consumed by Task 4.

- [ ] **Step 1: Write the failing test**

Extend `test/tests/certs_ip_validation/run.sh` — replace the heredoc's
closing `EOF` block to add these checks after the `is_ip_address` loop
(still inside the same `commands="$(cat <<'EOF' ... EOF)"` block, so it runs
in the same `docker run` invocation):

```bash
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
```

The full `test/tests/certs_ip_validation/run.sh` heredoc content after this
step (for reference — this is the complete file body between `<<'EOF'` and
`EOF`):

```bash
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker build -t acme-companion:dev .
./test/tests/certs_ip_validation/run.sh acme-companion:dev
```

Expected output includes both:
```
update_cert accepted a certificate mixing an IP address and a domain name, it should have rejected it.
update_cert accepted a DNS-01 challenge for an IP address certificate, it should have rejected it.
```
(`update_cert` will actually fail for unrelated reasons — no Docker socket,
no `nginx-proxy` container — but importantly it does **not** fail with our
new messages, so both `elif` branches will fire too; that's expected at this
stage and will resolve once Step 3 makes the function return 1 for our
specific reason *before* it reaches any of that other, unrelated code.)

- [ ] **Step 3: Write minimal implementation**

In `app/letsencrypt_service.sh`, the function currently reads (lines
164–176):

```bash
function update_cert {
    local cid="${1:?}"
    local hosts_var
    hosts_var="$(get_hosts_array_var "${cid}")" || return 1
    local -n hosts_array="${hosts_var}"
    # First domain will be our base domain
    local base_domain="${hosts_array[0]}"

    local wildcard_certificate='false'
    if [[ "${base_domain:0:2}" == "*." ]]; then
        wildcard_certificate='true'
    fi

    local should_restart_container='false'
```

Insert a new classification block between the `wildcard_certificate` `if`
block and `local should_restart_container='false'`:

```bash
function update_cert {
    local cid="${1:?}"
    local hosts_var
    hosts_var="$(get_hosts_array_var "${cid}")" || return 1
    local -n hosts_array="${hosts_var}"
    # First domain will be our base domain
    local base_domain="${hosts_array[0]}"

    local wildcard_certificate='false'
    if [[ "${base_domain:0:2}" == "*." ]]; then
        wildcard_certificate='true'
    fi

    # Classify this certificate's hosts: Let's Encrypt IP address
    # certificates have different requirements (HTTP-01/TLS-ALPN-01 only,
    # shortlived profile) than domain certificates, and can't mix the two.
    local -a ip_hosts=() dns_hosts=()
    local host
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
    if [[ ${#ip_hosts[@]} -gt 0 && ${#dns_hosts[@]} -gt 0 ]]; then
        echo "Error: cannot mix IP addresses and domain names in the same certificate (${base_domain}): IP(s) ${ip_hosts[*]}, domain(s) ${dns_hosts[*]}. Use ACME_SINGLE_DOMAIN_CERTS=true to split them into separate certificates."
        return 1
    fi

    local should_restart_container='false'
```

Then, the DNS-01 branch currently starts (around what was line 220, now a
few lines further down after the insertion above):

```bash
    elif [[ "${acme_challenge}" == "DNS-01" ]]; then
        # DNS-01 challenge
        local acmesh_dns_config_used='none'
```

Change it to:

```bash
    elif [[ "${acme_challenge}" == "DNS-01" ]]; then
        if [[ "${ip_certificate}" == 'true' ]]; then
            echo "Error: IP address certificates (${base_domain}) require the HTTP-01 or TLS-ALPN-01 challenge; DNS-01 is not supported by Let's Encrypt for IP identifiers."
            return 1
        fi
        # DNS-01 challenge
        local acmesh_dns_config_used='none'
```

- [ ] **Step 4: Run test to verify it passes**

```bash
docker build -t acme-companion:dev .
./test/tests/certs_ip_validation/run.sh acme-companion:dev
```

Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add app/letsencrypt_service.sh test/tests/certs_ip_validation/run.sh
git commit -m "feat: reject mixed IP/domain certs and DNS-01 for IP address certs"
```

---

### Task 3: Verify IPv6 addresses work as certificate directory/symlink names

**Files:**
- Modify: `test/tests/certs_ip_validation/run.sh` (extend, same file as Tasks 1–2)

**Interfaces:**
- Consumes: `create_links(base_domain, domain)` (already exists,
  `app/letsencrypt_service.sh:40`) — no production code change expected in
  this task; it's a verification step per spec §5.

- [ ] **Step 1: Write the test**

Append to the same heredoc in `test/tests/certs_ip_validation/run.sh` (after
the `ipdns_output` block from Task 2):

```bash
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
```

- [ ] **Step 2: Run test to verify it fails or passes, and diagnose either way**

```bash
docker build -t acme-companion:dev .
./test/tests/certs_ip_validation/run.sh acme-companion:dev
```

This exercises existing, unmodified code (`create_links`,
`mkdir -p`/`ln -sf` with a `:`-containing path). Expected: no output — Linux
filenames permit `:` (only `/` and NUL are forbidden), so directory
creation and symlinking should work unmodified.

If this instead fails: the failure is almost certainly in `create_links`
(`app/letsencrypt_service.sh:27-63`) or `create_link`
(`app/letsencrypt_service.sh:27-38`) mishandling the colon — read the
reported error, reproduce it with a plain `docker run --rm acme-companion:dev
sh -c "mkdir -p '/etc/nginx/certs/2001:db8::1' && ls -la /etc/nginx/certs/"`
to isolate whether it's a shell-quoting issue in this test or a real bug in
`create_link`, then fix the specific broken step. Do not add speculative
defensive code for a problem that doesn't reproduce.

- [ ] **Step 3: Commit**

```bash
git add test/tests/certs_ip_validation/run.sh
git commit -m "test: verify create_links handles IPv6 addresses"
```

---

### Task 4: Automatic defaults for IP address certificates

**Files:**
- Modify: `app/letsencrypt_service.sh:1-11` (top-of-file defaults)
- Modify: `app/letsencrypt_service.sh` cert-profile block (originally lines 466-473, shifted by Task 2's insertion — locate by the exact code shown below, don't rely on line numbers)
- Modify: `app/letsencrypt_service.sh` renew-after block (originally lines 522-527, same caveat)

**Interfaces:**
- Consumes: `ip_certificate` local variable from Task 2's classification
  block (`'true'`/`'false'`), `ACME_RENEW_AFTER_IP` global env var (new).
- Produces: for IP-only certificates with no explicit
  `ACME_CERT_PROFILE`/`ACME_RENEW_AFTER` override, `update_cert()` now
  passes `--cert-profile shortlived` and `--days 3` (default) to `acme.sh`.
  Verified end-to-end by Task 5 (no isolated unit test — the values only
  take effect once `acme.sh --issue` actually runs, which needs a real ACME
  account/CA per spec §"Testing").

- [ ] **Step 1: No new failing test in this task**

This task's behavior can only be observed once `acme.sh --issue` actually
runs against a real ACME server (building the params happens after account
registration, which needs network access) — see spec's "Testing" section.
Task 5 writes and runs the end-to-end test that exercises this code and
would fail without it. Proceed directly to the implementation; Task 5's
Step 2 is this task's "verify it fails" step.

- [ ] **Step 2: Write the implementation**

In `app/letsencrypt_service.sh`, near the top of the file (lines 1-11):

```bash
#!/bin/bash

# shellcheck source=app/functions.sh
source /app/functions.sh

CERTS_UPDATE_INTERVAL="${CERTS_UPDATE_INTERVAL:-3600}"
ACME_CA_URI="${ACME_CA_URI:-"https://acme-v02.api.letsencrypt.org/directory"}"
ACME_CA_TEST_URI="https://acme-staging-v02.api.letsencrypt.org/directory"
DEFAULT_KEY_SIZE="${DEFAULT_KEY_SIZE:-4096}"
RENEW_PRIVATE_KEYS="$(lc "${RENEW_PRIVATE_KEYS:-true}")"
ACME_RENEW_AFTER="${ACME_RENEW_AFTER:-60}"
```

Add one line after `ACME_RENEW_AFTER`:

```bash
ACME_RENEW_AFTER="${ACME_RENEW_AFTER:-60}"
ACME_RENEW_AFTER_IP="${ACME_RENEW_AFTER_IP:-3}"
```

Next, the certificate profile block (identify by this exact content,
originally around line 466):

```bash
    local -n acme_cert_profile="ACME_${cid}_CERT_PROFILE"
    if [[ -n "${acme_cert_profile}" ]]; then
        # Use per-container certificate profile
        params_issue_arr+=(--cert-profile "${acme_cert_profile}")
    elif [[ -n ${ACME_CERT_PROFILE// } ]]; then
        # Use default certificate profile
        params_issue_arr+=(--cert-profile "${ACME_CERT_PROFILE}")
    fi
```

Change to:

```bash
    local -n acme_cert_profile="ACME_${cid}_CERT_PROFILE"
    if [[ -n "${acme_cert_profile}" ]]; then
        # Use per-container certificate profile
        params_issue_arr+=(--cert-profile "${acme_cert_profile}")
    elif [[ -n ${ACME_CERT_PROFILE// } ]]; then
        # Use default certificate profile
        params_issue_arr+=(--cert-profile "${ACME_CERT_PROFILE}")
    elif [[ "${ip_certificate}" == 'true' ]]; then
        # Let's Encrypt requires the shortlived profile for IP address certificates
        params_issue_arr+=(--cert-profile shortlived)
    fi
```

Finally, the renewal threshold block (identify by this exact content,
originally around line 522):

```bash
    # Allow to override day to renew cert (per-container or global)
    local -n renew_after="ACME_${cid}_RENEW_AFTER"
    if [[ -z "${renew_after}" ]] || [[ ! "${renew_after}" =~ ^[0-9]+$ ]]; then
        renew_after="${ACME_RENEW_AFTER}"
    fi
    params_issue_arr+=(--days "${renew_after}")
```

Change to:

```bash
    # Allow to override day to renew cert (per-container or global)
    local -n renew_after="ACME_${cid}_RENEW_AFTER"
    if [[ -z "${renew_after}" ]] || [[ ! "${renew_after}" =~ ^[0-9]+$ ]]; then
        if [[ "${ip_certificate}" == 'true' ]]; then
            renew_after="${ACME_RENEW_AFTER_IP}"
        else
            renew_after="${ACME_RENEW_AFTER}"
        fi
    fi
    params_issue_arr+=(--days "${renew_after}")
```

- [ ] **Step 3: Commit**

```bash
git add app/letsencrypt_service.sh
git commit -m "feat: default IP address certificates to the shortlived profile and a 3-day renewal threshold"
```

---

### Task 5: End-to-end test against Pebble

**Files:**
- Create: `test/tests/certs_ip/run.sh`
- Modify: `test/config.sh` (register `certs_ip`, gated like `cert_profiles`)

**Interfaces:**
- Consumes: `run_le_container`, `run_nginx_container`, `wait_for_symlink`,
  `wait_for_conn`, `get_cert_validity_seconds` from
  `test/tests/test-functions.sh`; the smart defaults from Task 4; the
  validation from Task 2.

- [ ] **Step 1: Write the failing test**

Create `test/tests/certs_ip/run.sh`:

```bash
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
```

Register it in `test/config.sh`, gated the same way as `cert_profiles`
(both need the default Pebble config with multi-profile support):

```bash
# The cert_profiles test requires Pebble multiple profiles support from the default Pebble config
if [[ "${ACME_CA}" == 'pebble' && "${PEBBLE_CONFIG}" == 'pebble-config.json' ]]; then
	globalTests+=(
		cert_profiles
		certs_ip
	)
fi
```

- [ ] **Step 2: Run test to verify it fails, then set up the full local harness**

This test needs the full 2-container (`nginx-proxy` + `acme-companion`) test
topology plus Pebble, not just a bare `docker run`. `test/setup/setup-local.sh`
is this project's own local-test entry point (used instead of the individual
setup scripts): it reads `SETUP`/`ACME_CA`/`PEBBLE_CONFIG` (prompting
interactively if unset — export them to skip the prompts), adds `/etc/hosts`
entries for `TEST_DOMAINS`/`pebble`/`pebble-challtestsrv` (needs `sudo`; this
modifies a system file outside the repo — confirm with the user before
running this specific step if there's any doubt about doing that on this
machine), and calls `test/setup/pebble/setup-pebble.sh` +
`test/setup/setup-nginx-proxy.sh` for you. It writes the resolved
configuration to `test/local_test_env.sh`, which `test/run.sh` auto-sources.

```bash
export SETUP=2containers
export ACME_CA=pebble
export PEBBLE_CONFIG=pebble-config.json
bash test/setup/setup-local.sh --setup
docker build -t acme-companion:dev .
chmod +x test/tests/certs_ip/run.sh
bash test/run.sh -t certs_ip -c test/config.sh acme-companion:dev
```

Expected at this stage: the test fails, most likely at `wait_for_symlink`
timing out (certificate issuance either errors out or never completes)
since this is the first real run exercising Tasks 2 and 4 end-to-end.
Capture `docker logs <le_container_name>` on failure — the actual failure
reason (e.g. a Pebble validation error, a Host-header mismatch on the
nginx-proxy side, or something else) determines what, if anything, needs
fixing. This is expected debugging work, not a sign the plan is wrong;
apply superpowers:systematic-debugging if the cause isn't immediately
obvious from the logs.

- [ ] **Step 3: Fix forward until the test passes**

Common things to check if it doesn't pass on the first try, in likely order
of relevance:
- `docker logs <le_container_name>` for the actual `acme.sh --issue` error.
- Whether `nginx-proxy` generated a vhost/server block for the literal
  `10.30.50.1` string (`docker exec <nginx-proxy-container> cat
  /etc/nginx/conf.d/default.conf` or the relevant vhost file) — if it
  didn't, the issue is in how `nginx-proxy` (a separate image, pulled as
  `nginxproxy/nginx-proxy`) handles an IP-shaped `VIRTUAL_HOST`, which is
  out of this repo's control; document the finding rather than trying to
  patch another project's image.
- Whether Pebble's HTTP-01 validator actually reaches `10.30.50.1:80` at
  all (`docker logs pebble`).

- [ ] **Step 4: Run the full new + related test set to check for regressions**

```bash
bash test/run.sh -t certs_ip -t certs_ip_validation -t cert_profiles -t certs_single -t certs_san -c test/config.sh acme-companion:dev
```

Expected: all pass (no output per test, `passed` summary line each).

- [ ] **Step 5: Commit**

```bash
git add test/tests/certs_ip/run.sh test/config.sh
git commit -m "test: add end-to-end IP address certificate issuance test"
```

---

### Task 6: Documentation

**Files:**
- Create: `docs/IP-address-certificates.md`
- Modify: `README.md` (Features list, lines 31-38)
- Modify: `docs/Let's-Encrypt-and-ACME.md` (Certificate profile / Certificate renewal timing sections, lines 129-144)
- Modify: `docs/Environment-variables-reference.md` (acme-companion Container Variables table, lines 5-38)

**Interfaces:** None (documentation only).

- [ ] **Step 1: Write `docs/IP-address-certificates.md`**

```markdown
## IP address certificates

Since [January 2026](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability), Let's Encrypt issues certificates for public IP addresses, not just domain names. **acme-companion** supports this: set `ACME_HOST` (or the legacy `LETSENCRYPT_HOST`) on a proxied container to a public IPv4 or IPv6 address instead of a domain name, exactly as you would for a domain.

### Requirements and limitations

These come from Let's Encrypt itself, not from this project:

* Validation is restricted to the `HTTP-01` challenge (the default) or `TLS-ALPN-01`. `DNS-01` is not available for IP identifiers — there's no DNS to validate an IP against — and **acme-companion** will refuse to start an IP address certificate configured with `ACME_CHALLENGE=DNS-01`.
* **acme-companion** only implements the `HTTP-01` challenge for IP certificates; `TLS-ALPN-01` isn't implemented for domain certificates either and isn't required, since `HTTP-01` already covers IP identifiers.
* IP address certificates always use the `shortlived` certificate profile and are valid for about 160 hours (~6.7 days) instead of the usual 90 days.
* Wildcards don't apply to IP addresses.
* A single certificate cannot mix IP addresses and domain names — **acme-companion** rejects this combination with an explicit error. If you need both, request separate certificates (see [Separate certificate for each domain](./Let's-Encrypt-and-ACME.md#separate-certificate-for-each-domain)).
* The IP address must be publicly reachable on port `80` for the `HTTP-01` challenge to complete, same as for a domain.

See Let's Encrypt's own announcements for more background: [Announcing Six Day and IP Address Certificate Options](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs), [6-day and IP Address Certificates are Generally Available](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability).

### Automatic defaults

When **acme-companion** detects that a certificate's host is an IP address, it automatically:

* Requests the `shortlived` certificate profile (equivalent to setting [`ACME_CERT_PROFILE=shortlived`](./Let's-Encrypt-and-ACME.md#certificate-profile)), unless you've already set `ACME_CERT_PROFILE` yourself.
* Uses the `ACME_RENEW_AFTER_IP` environment variable (default `3` days) instead of `ACME_RENEW_AFTER` (default `60` days) to decide when to renew, unless you've already set `ACME_RENEW_AFTER` on that specific container.

You can override either default per container the same way you would for a domain certificate, by setting `ACME_CERT_PROFILE` and/or `ACME_RENEW_AFTER` explicitly.

### Example

```yaml
services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - certs:/etc/nginx/certs
      - vhost:/etc/nginx/vhost.d
      - html:/usr/share/nginx/html
      - /var/run/docker.sock:/tmp/docker.sock:ro

  acme-companion:
    image: nginxproxy/acme-companion
    volumes_from:
      - nginx-proxy
    volumes:
      - certs:/etc/nginx/certs
      - acme:/etc/acme.sh
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - DEFAULT_EMAIL=mail@yourdomain.tld

  webapp:
    image: yourwebapp
    environment:
      - VIRTUAL_HOST=203.0.113.42
      - ACME_HOST=203.0.113.42

volumes:
  certs:
  vhost:
  html:
  acme:
```

Replace `203.0.113.42` with your host's actual public IP address.
```

- [ ] **Step 2: Cross-link from `README.md`**

Current (lines 34-36):

```markdown
* Support creation of [Multi-Domain (SAN) Certificates](./docs/Let's-Encrypt-and-ACME.md#multi-domains-certificates).
* Support creation of [Wildcard Certificates](https://community.letsencrypt.org/t/acme-v2-production-environment-wildcards/55578) (with `DNS-01` challenge only).
* Creation of a strong [RFC7919 Diffie-Hellman Group](https://datatracker.ietf.org/doc/html/rfc7919#appendix-A) at startup.
```

Change to:

```markdown
* Support creation of [Multi-Domain (SAN) Certificates](./docs/Let's-Encrypt-and-ACME.md#multi-domains-certificates).
* Support creation of [Wildcard Certificates](https://community.letsencrypt.org/t/acme-v2-production-environment-wildcards/55578) (with `DNS-01` challenge only).
* Support creation of [IP address certificates](./docs/IP-address-certificates.md) (short-lived, `HTTP-01` challenge only).
* Creation of a strong [RFC7919 Diffie-Hellman Group](https://datatracker.ietf.org/doc/html/rfc7919#appendix-A) at startup.
```

- [ ] **Step 3: Cross-link from `docs/Let's-Encrypt-and-ACME.md`**

Current (lines 129-131, the "Certificate profile" section):

```markdown
#### Certificate profile

The `ACME_CERT_PROFILE` environment variable is used to select a specific profile offered by the CA. See for example [the list of profiles offered by Letsencrypt](https://letsencrypt.org/docs/profiles). Note that some profiles might reduce the validity period of the certificate; you might need to adjust the (global) `ACME_RENEW_AFTER` variable or set it per-container to make sure it gets updated in time.
```

Add a sentence at the end of that paragraph:

```markdown
#### Certificate profile

The `ACME_CERT_PROFILE` environment variable is used to select a specific profile offered by the CA. See for example [the list of profiles offered by Letsencrypt](https://letsencrypt.org/docs/profiles). Note that some profiles might reduce the validity period of the certificate; you might need to adjust the (global) `ACME_RENEW_AFTER` variable or set it per-container to make sure it gets updated in time. If `ACME_HOST` is a public IP address rather than a domain name, this is handled automatically — see [IP address certificates](./IP-address-certificates.md).
```

Current (line 143, "Certificate renewal timing" section) ends with:

```markdown
The `ACME_RENEW_AFTER` environment variable can be set on an application container to override the global renewal timing for that specific container's certificate. This is useful when using a CA or a [certificate profile](#certificate-profile) with a different validity period; for example, Buypass certificates have a lifespan of 180 days, and Let's Encrypt's offers [`tlsserver`](https://letsencrypt.org/docs/profiles/#tlsserver) (45 days) and [`shortlived`](https://letsencrypt.org/docs/profiles/#shortlived)  (180 hours) profiles. For example, Buypass certificates have a 180-day lifespan, so you might want to set `ACME_RENEW_AFTER=150` on those containers while keeping the default 60 days for Let's Encrypt certificates on others.
```

Add a sentence after it:

```markdown
The `ACME_RENEW_AFTER` environment variable can be set on an application container to override the global renewal timing for that specific container's certificate. This is useful when using a CA or a [certificate profile](#certificate-profile) with a different validity period; for example, Buypass certificates have a lifespan of 180 days, and Let's Encrypt's offers [`tlsserver`](https://letsencrypt.org/docs/profiles/#tlsserver) (45 days) and [`shortlived`](https://letsencrypt.org/docs/profiles/#shortlived)  (180 hours) profiles. For example, Buypass certificates have a 180-day lifespan, so you might want to set `ACME_RENEW_AFTER=150` on those containers while keeping the default 60 days for Let's Encrypt certificates on others.

[IP address certificates](./IP-address-certificates.md) use the separate `ACME_RENEW_AFTER_IP` variable (default `3` days) instead of `ACME_RENEW_AFTER`.
```

- [ ] **Step 4: Add the new variable to `docs/Environment-variables-reference.md`**

Current (line 16, in the "acme-companion Container Variables" table):

```markdown
| `ACME_RENEW_AFTER` | `60` (days) | `DEFAULT_RENEW` ⚠️ deprecated | [Container configuration](./Container-configuration.md#optional-container-environment-variables-for-custom-configuration) |
```

Add a new row right after it:

```markdown
| `ACME_RENEW_AFTER` | `60` (days) | `DEFAULT_RENEW` ⚠️ deprecated | [Container configuration](./Container-configuration.md#optional-container-environment-variables-for-custom-configuration) |
| `ACME_RENEW_AFTER_IP` | `3` (days) | — | [IP address certificates › Automatic defaults](./IP-address-certificates.md#automatic-defaults) |
```

(Keep the table alphabetically sorted — `ACME_RENEW_AFTER_IP` sorts right
after `ACME_RENEW_AFTER` and before `CA_BUNDLE`, so this insertion point is
already correct.)

- [ ] **Step 5: Commit**

```bash
git add docs/IP-address-certificates.md README.md "docs/Let's-Encrypt-and-ACME.md" docs/Environment-variables-reference.md
git commit -m "docs: document IP address certificate support"
```

---

### Task 7: Lint and full regression pass

**Files:** None new — verification only.

- [ ] **Step 1: Run shellcheck on every file touched by this plan**

```bash
docker run --rm -v "$PWD":/mnt -w /mnt koalaman/shellcheck:stable \
  app/functions.sh \
  app/letsencrypt_service.sh \
  test/tests/certs_ip_validation/run.sh \
  test/tests/certs_ip/run.sh \
  test/config.sh
```

Expected: no warnings/errors. Fix anything reported (the project's
`.shellcheckrc` at the repo root configures severity/excludes already in
effect for this invocation since shellcheck auto-loads it from the current
directory) and re-run until clean.

- [ ] **Step 2: Run the full local test suite**

```bash
bash test/run.sh -c test/config.sh acme-companion:dev
```

Expected: every test passes, including the pre-existing ones (regression
check) and all three new/modified ones (`certs_ip_validation`, `certs_ip`,
plus anything sharing code paths like `certs_san`/`cert_profiles`).

- [ ] **Step 3: Tear down the local test harness**

```bash
export SETUP=2containers
export ACME_CA=pebble
export PEBBLE_CONFIG=pebble-config.json
bash test/setup/setup-local.sh --teardown
```

(Also needs `sudo` to remove the `/etc/hosts` entries added in Task 5 Step
2 — same caveat applies.)

- [ ] **Step 4: Final read-through**

Re-read the full diff (`git diff main --stat` and `git log --oneline
main..HEAD`) against `docs/superpowers/specs/2026-08-05-ip-address-certificates-design.md`
section by section, confirming each design section has a corresponding
change. No commit for this step — it's a review checkpoint before calling
the feature done.
