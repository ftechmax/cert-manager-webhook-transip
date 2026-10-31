package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/transip/gotransip/v6"
	"github.com/transip/gotransip/v6/domain"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(GroupName, &transipDNSProviderSolver{})
}

type transipDNSProviderSolver struct {
	client kubernetes.Interface
}

type transipDNSProviderConfig struct {
	TTL                 int                       `json:"ttl"`
	PrivateKeySecretRef corev1.SecretKeySelector  `json:"privateKeySecretRef"`
}

func (s *transipDNSProviderSolver) Name() string {
	return "transip"
}

func (s *transipDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	s.client = cl
	return nil
}

func (s *transipDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	repo, err := s.newDomainRepo(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("creating transip client: %w", err)
	}

	domainName := extractDomainName(ch.ResolvedZone)
	recordName := extractRecordName(ch.ResolvedFQDN, domainName)
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 300
	}

	entry := domain.DNSEntry{
		Name:    recordName,
		Expire:  ttl,
		Type:    "TXT",
		Content: ch.Key,
	}

	// Check if the record already exists (idempotent)
	entries, err := repo.GetDNSEntries(domainName)
	if err != nil {
		return fmt.Errorf("listing dns entries for %s: %w", domainName, err)
	}
	for _, e := range entries {
		if e.Name == recordName && e.Type == "TXT" && e.Content == ch.Key {
			klog.Infof("TXT record %s already exists for %s, skipping", recordName, domainName)
			return nil
		}
	}

	klog.Infof("Creating TXT record %s for %s", recordName, domainName)
	if err := repo.AddDNSEntry(domainName, entry); err != nil {
		return fmt.Errorf("adding dns entry: %w", err)
	}
	return nil
}

func (s *transipDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	repo, err := s.newDomainRepo(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("creating transip client: %w", err)
	}

	domainName := extractDomainName(ch.ResolvedZone)
	recordName := extractRecordName(ch.ResolvedFQDN, domainName)

	entries, err := repo.GetDNSEntries(domainName)
	if err != nil {
		return fmt.Errorf("listing dns entries for %s: %w", domainName, err)
	}

	for _, e := range entries {
		if e.Name == recordName && e.Type == "TXT" && e.Content == ch.Key {
			klog.Infof("Removing TXT record %s from %s", recordName, domainName)
			if err := repo.RemoveDNSEntry(domainName, e); err != nil {
				return fmt.Errorf("removing dns entry: %w", err)
			}
			return nil
		}
	}

	klog.Infof("TXT record %s not found for %s, nothing to clean up", recordName, domainName)
	return nil
}

func (s *transipDNSProviderSolver) newDomainRepo(cfg transipDNSProviderConfig, namespace string) (domain.Repository, error) {
	secret, err := s.client.CoreV1().Secrets(namespace).Get(context.Background(), cfg.PrivateKeySecretRef.Name, metav1.GetOptions{})
	if err != nil {
		return domain.Repository{}, fmt.Errorf("reading secret %s/%s: %w", namespace, cfg.PrivateKeySecretRef.Name, err)
	}

	key := cfg.PrivateKeySecretRef.Key
	if key == "" {
		key = "privateKey"
	}
	privateKey, ok := secret.Data[key]
	if !ok {
		return domain.Repository{}, fmt.Errorf("key %q not found in secret %s/%s", key, namespace, cfg.PrivateKeySecretRef.Name)
	}

	accountName := string(secret.Data["accountName"])
	if accountName == "" {
		return domain.Repository{}, fmt.Errorf("key \"accountName\" not found in secret %s/%s", namespace, cfg.PrivateKeySecretRef.Name)
	}

	client, err := gotransip.NewClient(gotransip.ClientConfiguration{
		AccountName:      accountName,
		PrivateKeyReader: bytes.NewReader(privateKey),
	})
	if err != nil {
		return domain.Repository{}, fmt.Errorf("creating gotransip client: %w", err)
	}

	return domain.Repository{Client: client}, nil
}

func loadConfig(cfgJSON *extapi.JSON) (transipDNSProviderConfig, error) {
	cfg := transipDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("unmarshalling solver config: %w", err)
	}
	return cfg, nil
}

func extractDomainName(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

func extractRecordName(fqdn, domainName string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	if name, ok := strings.CutSuffix(fqdn, "."+domainName); ok {
		return name
	}
	return fqdn
}
