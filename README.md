# cert-manager webhook solver for TransIP

A [cert-manager](https://cert-manager.io/) DNS01 webhook solver for issuing Let's Encrypt certificates for [TransIP](https://www.transip.nl/) domains.

## Install

Requires Kubernetes with cert-manager installed and a TransIP account with API access enabled.

### 1. Create credentials

Generate an API key pair in the [TransIP control panel](https://www.transip.nl/cp/account/api/) with **"Only accept IP addresses from the whitelist" turned off**. The webhook requests tokens usable from any IP; whitelisted keys reject these requests.

```bash
kubectl -n cert-manager create secret generic transip-credentials \
  --from-file=privateKey=/path/to/transip-api-key.pem \
  --from-literal=accountName=your-transip-username
```

If you rename the secret, update `resourceNames` in [secret-rbac.yaml](deploy/base/secret-rbac.yaml) and the solver's `privateKeySecretRef.name` in [clusterissuer.yaml](deploy/base/clusterissuer.yaml).

### 2. Configure

Set `email` (Let's Encrypt contact) and `image` (full container image reference) in `deploy/overlays/local/settings.yaml`.

For production, copy `deploy/overlays/production/settings.example.yaml` to `settings.yaml` in the same directory and edit it. Production settings are git-ignored.

### 3. Deploy

```bash
kubectl apply -k deploy/overlays/local
# Or:
kubectl apply -k deploy/overlays/production
```

This creates two ClusterIssuers: `letsencrypt-transip-staging` and `letsencrypt-transip-production`.

## Usage

Save as `certificate.yaml`, replacing the domain and namespace:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
  namespace: default
spec:
  secretName: my-cert-tls
  issuerRef:
    name: letsencrypt-transip-staging
    kind: ClusterIssuer
  dnsNames:
    - example.nl
    - "*.example.nl"
```

```bash
kubectl apply -f certificate.yaml
```

Once issuance works, change `issuerRef.name` to `letsencrypt-transip-production` and apply again. The certificate and private key are stored in `my-cert-tls` in the Certificate's namespace.

## Solver configuration

Options in the webhook solver's `config` block in [clusterissuer.yaml](deploy/base/clusterissuer.yaml):

| Field | Default | Description |
| ----- | ------- | ----------- |
| `privateKeySecretRef.name` | Required | Credentials secret name |
| `privateKeySecretRef.key` | `privateKey` | Secret key containing the PEM private key |
| `accountNameKey` | `accountName` | Secret key containing the TransIP account name |
| `ttl` | `300` | TXT record TTL in seconds; minimum 60 |

ClusterIssuers use credentials in `cert-manager`. Namespaced Issuers need credentials in their own namespace and a Role and RoleBinding granting the webhook `get` on that secret.
