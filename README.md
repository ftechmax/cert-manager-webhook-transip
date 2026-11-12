# cert-manager webhook solver for TransIP

A [cert-manager](https://cert-manager.io/) DNS01 webhook solver for issuing Let's Encrypt certificates for [TransIP](https://www.transip.nl/) domains.

## Install

Requires Kubernetes with cert-manager installed in `cert-manager`, `kubectl` with Kustomize support, and a TransIP account with API access enabled.

### 1. Create credentials

Generate an API key pair in the [TransIP control panel](https://www.transip.nl/cp/account/api/).

```bash
kubectl -n cert-manager create secret generic transip-credentials \
  --from-file=privateKey=/path/to/transip-api-key.pem \
  --from-literal=accountName=your-transip-username
```

### 2. Configure

For production, create your settings file:

```bash
cp deploy/overlays/production/settings.example.yaml deploy/overlays/production/settings.yaml
```

Set `email` to your Let's Encrypt contact address and `image` to the full image reference from [GHCR](https://github.com/ftechmax/cert-manager-webhook-transip/pkgs/container/cert-manager-webhook-transip).

For local development, edit `deploy/overlays/local/settings.yaml` instead.

Set `TOKEN_WHITELISTED=true` on the webhook container to request IP-restricted tokens (default: `false`). See [TransIP authentication](https://api.transip.eu/rest/docs.html#header-authentication).

### 3. Deploy

```bash
kubectl apply -k deploy/overlays/production
kubectl -n cert-manager rollout status deployment/transip-webhook --timeout=120s
kubectl wait --for=condition=Available apiservice/v1alpha1.acme.ftechmax.net --timeout=120s
```

Use `deploy/overlays/local` for a local deployment. Both overlays create two ClusterIssuers: `letsencrypt-transip-staging` and `letsencrypt-transip-production`.

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

Licensed under [MIT](LICENSE).
