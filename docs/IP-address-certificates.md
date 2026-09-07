## IP address certificates

Some ACME CAs issue certificates for public IP addresses, not just domain names: [Let's Encrypt since January 2026](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability), and [Google Trust Services](./Google-Trust-Services.md#ip-address-certificates). **acme-companion** supports this: set `ACME_HOST` (or the legacy `LETSENCRYPT_HOST`) on a proxied container to a public IPv4 or IPv6 address instead of a domain name, exactly as you would for a domain.

### Requirements and limitations

These come from the CAs and the CA/Browser Forum baseline requirements, not from this project:

* Validation is restricted to the `HTTP-01` challenge (the default) or `TLS-ALPN-01`. `DNS-01` is not available for IP identifiers — there's no DNS to validate an IP against — and **acme-companion** will refuse to start an IP address certificate configured with `ACME_CHALLENGE=DNS-01`.
* **acme-companion** only implements the `HTTP-01` challenge for IP certificates; `TLS-ALPN-01` isn't implemented for domain certificates either and isn't required, since `HTTP-01` already covers IP identifiers.
* Wildcards don't apply to IP addresses.
* A single certificate cannot mix IP addresses and domain names — **acme-companion** rejects this combination with an explicit error. If you need both, request separate certificates (see [Separate certificate for each domain](./Let's-Encrypt-and-ACME.md#separate-certificate-for-each-domain)).
* The IP address must be publicly reachable on port `80` for the `HTTP-01` challenge to complete, same as for a domain.

The certificate profile and lifetime depend on the CA:

| CA | `ACME_CA_URI` | Profile used for IP addresses | Lifetime | Account |
|---|---|---|---|---|
| Let's Encrypt (default) | `https://acme-v02.api.letsencrypt.org/directory` | `shortlived` (mandatory) | ~160 hours (~6.7 days) | No EAB needed |
| Google Trust Services | `https://dv.acme-v02.api.pki.goog/directory` | CA default (`standard`) | 90 days | [EAB credentials required](./Google-Trust-Services.md#account) |

See Let's Encrypt's own announcements for more background: [Announcing Six Day and IP Address Certificate Options](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs), [6-day and IP Address Certificates are Generally Available](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability). For Google Trust Services, see [its IP certificate FAQ entry](https://developers.google.com/public-key-infrastructure/faq/ip-certificates).

### Automatic defaults

When **acme-companion** detects that a certificate's host is an IP address, it automatically:

* Requests the certificate profile the configured CA requires for IP addresses, unless you've already set [`ACME_CERT_PROFILE`](./Let's-Encrypt-and-ACME.md#certificate-profile) yourself. That's `shortlived` on Let's Encrypt, which only issues IP address certificates under that profile. Google Trust Services and ZeroSSL don't offer a `shortlived` profile and would reject it, so no profile is requested there and the CA's own default applies.
* Uses the `ACME_RENEW_AFTER_IP` environment variable (default `3` days) instead of `ACME_RENEW_AFTER` (default `60` days) to decide when to renew, but only for certificates actually requested under a `shortlived` profile — those are the ones the 60 days default would never renew in time. A 90-day IP address certificate from Google Trust Services keeps the regular `ACME_RENEW_AFTER` threshold.

You can override either default per container the same way you would for a domain certificate, by setting `ACME_CERT_PROFILE` and/or `ACME_RENEW_AFTER` explicitly.

Should a CA change which profile it requires for IP addresses, `ACME_IP_CERT_PROFILE` on the **acme-companion** container overrides the automatic choice without pinning a profile on domain certificates too: set it to a profile name to request that profile for every IP address certificate, or to `none` to request no profile at all. It defaults to `auto`, the per-CA behaviour described above, and is ignored when `ACME_CERT_PROFILE` is set.

### Example

```yaml
services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy:1.11.6
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - certs:/etc/nginx/certs
      - vhost:/etc/nginx/vhost.d
      - html:/usr/share/nginx/html
      - /var/run/docker.sock:/tmp/docker.sock:ro

  acme-companion:
    image: kineviz/nginx-acme-companion:2.8.2
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

This example uses the default CA, Let's Encrypt, so the certificate is issued under the `shortlived` profile and renewed every 3 days. For the same setup against Google Trust Services, see [its IP address certificate example](./Google-Trust-Services.md#ip-address-certificates).
