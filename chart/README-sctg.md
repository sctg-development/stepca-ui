# step-certificates (sctg-development fork)

Upstream chart `step-certificates` 1.30.1 (Smallstep, Apache-2.0) with additions, all **off by default**:

| Values | Adds |
|---|---|
| `ui.*` | stepca-ui Deployment, Service, PVC (SQLite), ConfigMap/Secret (profiles, users, JWK keys), read-only RBAC for the cert-manager inventory, optional NetworkPolicy |
| `exposure.*` | Ingress with TLS passthrough to the CA, and a plain-HTTP Service + Ingress for the CRL |
| `clusterIssuer.*` | cert-manager `ClusterIssuer` (ACME) towards the CA, with a pod affinity for the HTTP-01 solvers |

Chart version `1.31.0`; the CA itself is unchanged (`appVersion` 0.30.2). To keep resource names (and the
database PVC) of an existing release, set `fullnameOverride`.

## UI values

```yaml
ui:
  enabled: true
  defaultProfile: ike
  profiles:               # map: the keys may be split into a SOPS file (Helm replaces lists, merges maps)
    ike:  {label: "IKEv2", provisioner: jwk-ike, keyType: RSA, keySize: 2048, defaultDays: 365, maxDays: 365}
    mtls: {label: "mTLS client", provisioner: jwk-mtls, defaultDays: 90, maxDays: 365}
  profileKeys:            # private JWK of each provisioner (JSON string) -> secrets file
    ike: '{"kty":"EC", ...}'
    mtls: '{"kty":"EC", ...}'
  users:                  # local accounts (bcrypt hashes)
    ronan: {passwordHash: "$2a$10$...", role: admin}
  auth:                   # or: behind oauth2-proxy
    trustProxy: true
    adminEmails: [admin@example.org]
  networkPolicy:          # mandatory with trustProxy: only the proxy may reach the UI
    enabled: true
    allowFrom:
      - podSelector: {matchLabels: {app.kubernetes.io/name: oauth2-proxy}}
```

The provisioners themselves (`jwk-ike`, ...) are declared in `inject.config.files.ca.json.authority.provisioners`
as usual, with the **public** JWK in `key`. `ui.profiles.<name>.provisioner` must match a provisioner name.
