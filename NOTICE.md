# Origin

stepca-ui started as a detached copy of [KyleMercer/step-ui](https://github.com/KyleMercer/step-ui)
(itself based on work by Marcin Kruszyński), taken at commit
`c1b0a9d3ba162157468a466da831234b27d2d91c`. The upstream README declares the MIT license; the upstream
repository ships no LICENSE file, so the copyright lines in [LICENSE](LICENSE) credit its authors as listed
in its git history. The history was not kept.

Also forked: the Helm chart `step-certificates` 1.30.1 from
[smallstep/helm-charts](https://github.com/smallstep/helm-charts) (Apache-2.0), see `chart/step-certificates/`.

# Changes from upstream step-ui

- one image: the Go backend serves the statically exported UI (same origin, no CORS, no bearer token to share)
- issuance **profiles** (provisioner + JWK key + validity limits + key type) instead of one provisioner/password
- accounts from a file (`USERS_FILE`: username / bcrypt hash / role), and trusted-proxy authentication
  (oauth2-proxy e-mail header, role by e-mail list)
- CSRF guard (`X-Requested-With`), `Secure`/`SameSite=Lax` session cookies, `Secure` behind HTTPS
- inventory: *source* column (UI / cert-manager / import), read-only sync of cert-manager Certificates issued
  by step-ca, import of existing PEM certificates, "expiring within 30 days" filter, expired status computed live
- renew uses the profile's default validity (was a fixed 90 days); revoke uses the certificate's profile
- Helm chart with the UI, CRL exposure and a cert-manager ClusterIssuer
