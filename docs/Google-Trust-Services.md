## Google Trust Services

[Google Trust Service](https://pki.goog/) is an ACME CA with generous default quota and high ubiquity. 

Using Google Trust Services through an ACME client, like in this container, allows for unlimited 90 days and multi-domains (SAN) certificates.

### Activation

Google Trust Services support is activated when the `ACME_CA_URI` environment variable is set to the Google Trust Services ACME endpoint (`https://dv.acme-v02.api.pki.goog/directory`).

Google Trust Services also runs a staging endpoint, `https://dv.acme-v02.test-api.pki.goog/directory`, which issues untrusted test certificates. Point `ACME_CA_URI` at it while setting things up so that failed attempts don't consume your production quota. Note that `LETSENCRYPT_TEST=true` selects Let's Encrypt's staging endpoint, not this one.

### Account

Google Trust Services requires the use of an externally bound account. First create a [Google Trust Services account](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial#request-key-hmac):

- provide the pre-generated [EAB credentials](https://tools.ietf.org/html/rfc8555#section-7.3.4) using the `ACME_EAB_KID` and `ACME_EAB_HMAC_KEY` environment variables.

With the Google Cloud CLI, that is:

```console
$ gcloud services enable publicca.googleapis.com
$ gcloud publicca external-account-keys create
```

The command returns a `keyId` (use it as `ACME_EAB_KID`) and a `b64MacKey` (use it as `ACME_EAB_HMAC_KEY`). Each set of credentials registers a single ACME account and must be used within 7 days of being created.

These variables can be set on the proxied containers or directly on the **acme-companion** container.

When registering a new ACME account with EAB, Google Trust Services expects a contact email. Set either `ACME_EMAIL` on the proxied container or `DEFAULT_EMAIL` on the **acme-companion** container so the initial `acme.sh --register-account` call includes it.

If both are unset or blank, **acme-companion** will still try to register the EAB account without an email and log a warning, but Google Trust Services may reject the registration.

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
      - ACME_CA_URI=https://dv.acme-v02.api.pki.goog/directory
      - ACME_EAB_KID=your-eab-key-id
      - ACME_EAB_HMAC_KEY=your-eab-hmac-key

  webapp:
    image: yourwebapp
    environment:
      - VIRTUAL_HOST=yourdomain.tld
      - ACME_HOST=yourdomain.tld

volumes:
  certs:
  vhost:
  html:
  acme:
```

Keep the EAB credentials out of the compose file itself in production: pass them through an `.env` file, a secret manager, or your orchestrator's own secret mechanism.

### Certificate profiles

Google Trust Services implements the [ACME profiles extension](https://developers.google.com/public-key-infrastructure/profiles) and offers two profiles:

* `standard` (the default): certificates compatible with a wide range of browsers and clients.
* `minimal`: a smaller served chain, issued from an ECC chain, with `subject:commonName`, the SKID extension, `basicConstraints` and the `keyEncipherment` key usage omitted.

Select one with [`ACME_CERT_PROFILE`](./Let's-Encrypt-and-ACME.md#certificate-profile), globally on the **acme-companion** container or per proxied container. Let's Encrypt's profile names (`classic`, `tlsserver`, `shortlived`) don't exist at Google Trust Services and will be rejected.

### IP address certificates

Google Trust Services [issues certificates containing an IP address in the SAN extension](https://developers.google.com/public-key-infrastructure/faq/ip-certificates). Request one exactly as you would with any other CA — set `ACME_HOST` to a public IP address instead of a domain name — and see [IP address certificates](./IP-address-certificates.md) for the rules that apply to all CAs.

Two things differ from Let's Encrypt:

* Google Trust Services issues IP address certificates under its regular profile, not under a dedicated short-lived one. **acme-companion** therefore doesn't request Let's Encrypt's `shortlived` profile when the CA is Google Trust Services, and keeps the regular `ACME_RENEW_AFTER` (60 days) renewal threshold instead of the 3 days used for short-lived certificates.
* The account still needs EAB credentials, just like for a domain certificate.

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
      - ACME_CA_URI=https://dv.acme-v02.api.pki.goog/directory
      - ACME_EAB_KID=your-eab-key-id
      - ACME_EAB_HMAC_KEY=your-eab-hmac-key

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

Replace `203.0.113.42` with your host's actual public IP address, which must be reachable on port `80` for the `HTTP-01` challenge.
