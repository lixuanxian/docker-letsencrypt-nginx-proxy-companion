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
