# stepca-ui

Web administration for a [Smallstep step-ca](https://smallstep.com/docs/step-ca/) certificate authority:

- **monitor** certificates (expiry, status, source), including the ones cert-manager obtained through ACME
- **issue** certificates by hand from named **profiles** (server TLS, IKEv2, mTLS client, ...), sign CSRs,
  renew and revoke
- two roles: `admin` and `viewer`

> Provenance: detached copy of [KyleMercer/step-ui](https://github.com/KyleMercer/step-ui) (MIT), see [NOTICE.md](NOTICE.md).
> The upstream author recommends it only for homelab use. Review the security notes below before exposing it.

## How it works

The Go backend serves the static UI and the JSON API. It does not hold a CA key: to issue, it asks the `step`
CLI for a one-time token signed with the **provisioner's JWK private key** of the selected profile, then
calls `step ca certificate` / `sign` / `revoke`. step-ca stays authoritative (its provisioner claims and
templates apply). Issued-certificate metadata and the audit log live in SQLite (`DB_PATH`).

step-ca has no "list issued certificates" API, so the inventory is built from what the UI issues, what you
import (PEM) and, in a cluster, the cert-manager `Certificate`s whose `issuerRef` is the step-ca issuer
(read-only, `K8S_SYNC=true`). Certificates issued some other way (CLI, scripts) do not show up unless you
import them.

## Configuration (environment)

| Variable | Meaning |
|---|---|
| `CA_URL` | step-ca URL used by the backend (may be in-cluster) |
| `PUBLIC_CA_URL`, `ACME_PROVISIONER` | address and ACME provisioner shown in Settings (what clients use) |
| `CA_ROOT_FILE` / `CA_ROOT_FINGERPRINT` | the root certificate file, or the fingerprint to download it with |
| `PROFILES_FILE` | YAML, see below. Without it, one `default` profile from `PROVISIONER_NAME`/`PROVISIONER_PASSWORD` |
| `USERS_FILE` | YAML `users: [{username, passwordHash (bcrypt), role: admin\|viewer}]`, synced at start |
| `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` | seed one admin when the user table is empty |
| `TRUST_PROXY_AUTH`, `PROXY_USER_HEADER`, `ADMIN_EMAILS`, `VIEWER_EMAILS` | trusted-proxy (oauth2-proxy) authentication |
| `COOKIE_SECURE` | force the `Secure` flag (also set automatically when `X-Forwarded-Proto: https`) |
| `K8S_SYNC`, `K8S_ISSUER_NAME`, `K8S_SYNC_INTERVAL` | cert-manager inventory: mirror the `Certificate`s of these issuers (comma separated); needs RBAC to list `certificates`, never reads Secrets |
| `DB_PATH`, `PORT`, `STATIC_DIR` | storage, listen port, UI directory |

```yaml
# PROFILES_FILE
profiles:
  - name: ike
    label: "IKEv2 gateway"
    provisioner: jwk-ike
    keyFile: /etc/stepca-ui/keys/jwk-ike.json   # the provisioner's private JWK (encrypted: add passwordFile)
    keyType: RSA
    keySize: 2048
    defaultDays: 365
    maxDays: 365
```

Generate a password hash: `htpasswd -nbBC 10 "" 'password' | tr -d ':\n' | sed 's/$2y/$2a/'`.

## Security notes

- The UI can issue and revoke certificates: anyone who is `admin` has the power of the profiles' provisioners.
  Use dedicated provisioners with tight claims (max duration, SAN rules through templates) for the UI.
- **Trusted-proxy mode** trusts the identity header. Only enable it when the UI is reachable *only* through
  the proxy (the chart can create a NetworkPolicy for that). Local accounts and proxy mode can coexist.
- State-changing requests need `X-Requested-With: stepca-ui` (CSRF guard); sessions are `HttpOnly`, `SameSite=Lax`,
  and `Secure` over HTTPS.
- Private keys of server-side issued certificates are returned once in the download bundle and are not stored.

## Build and run

```bash
docker build -t stepca-ui --build-arg APP_VERSION=1.0.0 .
docker run --rm -p 8080:8080 -e CA_URL=... -e CA_ROOT_FILE=... -v ...:/etc/stepca-ui ... stepca-ui
```

Development: `cd backend && go run ./cmd` (with `CORS_ALLOWED_ORIGIN=http://localhost:3000`) and
`cd frontend && NEXT_PUBLIC_API_URL=http://localhost:8080 npm run dev`. Tests: `cd backend && go test ./...`.

## Helm chart

`chart/step-certificates` is the upstream chart 1.30.1 plus: the UI (`ui.*`), CRL/HTTPS exposure
(`exposure.*`) and a cert-manager `ClusterIssuer` (`clusterIssuer.*`). See [chart/README-sctg.md](chart/README-sctg.md).

## License

MIT, see [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
