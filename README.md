# cert-manager webhook solver for TransIP

A [cert-manager](https://cert-manager.io/) ACME DNS01 webhook solver for [TransIP](https://www.transip.nl/) domains. Automates Let's Encrypt certificate provisioning by creating DNS TXT records via the TransIP REST API.

## Prerequisites

- Kubernetes cluster with cert-manager installed
- TransIP account with API access enabled
- TransIP RSA private key (generated in the [TransIP control panel](https://www.transip.nl/cp/account/api/))

## Build

```bash
make build             # build binary locally
make docker-build # build and push container image
```

## Deploy

### 1. Create the TransIP credentials secret

```bash
kubectl -n cert-manager create secret generic transip-credentials \
  --from-file=privateKey=/path/to/transip-api-key.pem \
  --from-literal=accountName=your-transip-username
```

### 2. Set your ACME email

Edit `config.env` in the overlay you deploy (`deploy/overlays/local` or `deploy/overlays/production`):

```
email=you@example.com
```

### 3. Apply

```bash
make deploy               # local overlay, ~/.kube/config
make deploy PRODUCTION=1  # production overlay, ~/.kube/prd
```

### 4. Verify

```bash
# Webhook pod should be Running
kubectl -n cert-manager get pods -l app=transip-webhook

# APIService should be Available
kubectl get apiservice v1alpha1.acme.transip.nl
```

## Usage

### Standalone Certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
  namespace: istio-ingress
spec:
  secretName: my-cert-tls
  issuerRef:
    name: letsencrypt-staging # switch to letsencrypt-production once verified
    kind: ClusterIssuer
  dnsNames:
    - example.nl
    - "*.example.nl"
```

### With Istio Gateway API

Add the `cert-manager.io/cluster-issuer` annotation to your Gateway and add HTTPS listeners — cert-manager will automatically create Certificate resources for each listener:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: gateway
  namespace: istio-ingress
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-production
spec:
  gatewayClassName: istio
  listeners:
    - name: https
      hostname: "example.nl"
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - name: example-nl-tls
      allowedRoutes:
        namespaces:
          from: All
```

See `examples/` for more complete examples.
