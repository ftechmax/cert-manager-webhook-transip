IMAGE_NAME ?= registry:5000/cert-manager-webhook-transip
IMAGE_TAG ?= latest

# Target the production cluster with PRODUCTION=1, e.g. `make deploy PRODUCTION=1`
ifneq ($(filter 1 true yes,$(PRODUCTION)),)
KUBE_CONFIG := $(HOME)/.kube/prd
OVERLAY := production
else
KUBE_CONFIG := $(HOME)/.kube/config
OVERLAY := local
endif

.PHONY: build clean docker-build deploy

build:
	CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

docker-build:
	krun --kubeconfig $(KUBE_CONFIG) build cert-manager-webhook-transip

deploy:
	kubectl --kubeconfig $(KUBE_CONFIG) apply -k deploy/overlays/$(OVERLAY)
	kubectl --kubeconfig $(KUBE_CONFIG) -n cert-manager rollout restart deployment/transip-webhook
	kubectl --kubeconfig $(KUBE_CONFIG) -n cert-manager rollout status deployment/transip-webhook --timeout=120s

clean:
	rm -f webhook
