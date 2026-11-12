package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

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

const (
	defaultTTL            = 300
	minTTL                = 60
	defaultPrivateKeyKey  = "privateKey"
	defaultAccountNameKey = "accountName"

	apiTimeout = 30 * time.Second
)

func main() {
	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(groupName, &transipSolver{newRepo: newTransipRepo})
}

type dnsRepository interface {
	GetDNSEntries(domainName string) ([]domain.DNSEntry, error)
	AddDNSEntry(domainName string, entry domain.DNSEntry) error
	RemoveDNSEntry(domainName string, entry domain.DNSEntry) error
}

type transipSolver struct {
	client  kubernetes.Interface
	newRepo func(accountName string, privateKey []byte) (dnsRepository, error)
}

type solverConfig struct {
	TTL                 int                      `json:"ttl"`
	PrivateKeySecretRef corev1.SecretKeySelector `json:"privateKeySecretRef"`
	AccountNameKey      string                   `json:"accountNameKey"`
}

type challenge struct {
	repo       dnsRepository
	domainName string
	entry      domain.DNSEntry
}

func (s *transipSolver) Name() string {
	return "transip"
}

func (s *transipSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	s.client = client
	return nil
}

func (s *transipSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	c, err := s.prepare(ch)
	if err != nil {
		return err
	}

	entries, err := c.repo.GetDNSEntries(c.domainName)
	if err != nil {
		return fmt.Errorf("listing dns entries for %s: %w", c.domainName, err)
	}
	if _, found := c.find(entries); found {
		klog.Infof("TXT record %s already exists for %s, skipping", c.entry.Name, c.domainName)
		return nil
	}

	klog.Infof("Creating TXT record %s for %s", c.entry.Name, c.domainName)
	if err := c.repo.AddDNSEntry(c.domainName, c.entry); err != nil {
		return fmt.Errorf("adding dns entry: %w", err)
	}
	return nil
}

func (s *transipSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	c, err := s.prepare(ch)
	if err != nil {
		return err
	}

	entries, err := c.repo.GetDNSEntries(c.domainName)
	if err != nil {
		return fmt.Errorf("listing dns entries for %s: %w", c.domainName, err)
	}
	entry, found := c.find(entries)
	if !found {
		klog.Infof("TXT record %s not found for %s, nothing to clean up", c.entry.Name, c.domainName)
		return nil
	}

	klog.Infof("Removing TXT record %s from %s", c.entry.Name, c.domainName)
	if err := c.repo.RemoveDNSEntry(c.domainName, entry); err != nil {
		return fmt.Errorf("removing dns entry: %w", err)
	}
	return nil
}

// Match the key as well as the name so apex and wildcard challenges can coexist.
func (c challenge) find(entries []domain.DNSEntry) (domain.DNSEntry, bool) {
	for _, e := range entries {
		if strings.EqualFold(e.Name, c.entry.Name) && e.Type == c.entry.Type && e.Content == c.entry.Content {
			return e, true
		}
	}
	return domain.DNSEntry{}, false
}

func (s *transipSolver) prepare(ch *v1alpha1.ChallengeRequest) (challenge, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return challenge{}, fmt.Errorf("loading config: %w", err)
	}

	domainName, recordName, err := splitFQDN(ch.ResolvedFQDN, ch.ResolvedZone)
	if err != nil {
		return challenge{}, err
	}

	accountName, privateKey, err := s.loadCredentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return challenge{}, err
	}

	repo, err := s.newRepo(accountName, privateKey)
	if err != nil {
		return challenge{}, fmt.Errorf("creating transip client: %w", err)
	}

	return challenge{
		repo:       repo,
		domainName: domainName,
		entry: domain.DNSEntry{
			Name:    recordName,
			Expire:  cfg.TTL,
			Type:    "TXT",
			Content: ch.Key,
		},
	}, nil
}

func (s *transipSolver) loadCredentials(cfg solverConfig, namespace string) (accountName string, privateKey []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	name := cfg.PrivateKeySecretRef.Name
	secret, err := s.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", nil, fmt.Errorf("reading secret %s/%s: %w", namespace, name, err)
	}

	privateKey = secret.Data[cfg.PrivateKeySecretRef.Key]
	if len(privateKey) == 0 {
		return "", nil, fmt.Errorf("key %q not found in secret %s/%s", cfg.PrivateKeySecretRef.Key, namespace, name)
	}
	accountName = string(secret.Data[cfg.AccountNameKey])
	if accountName == "" {
		return "", nil, fmt.Errorf("key %q not found in secret %s/%s", cfg.AccountNameKey, namespace, name)
	}
	return accountName, privateKey, nil
}

var transipHTTPClient = &http.Client{Timeout: apiTimeout}

func newTransipRepo(accountName string, privateKey []byte) (dnsRepository, error) {
	client, err := gotransip.NewClient(gotransip.ClientConfiguration{
		AccountName:      accountName,
		PrivateKeyReader: bytes.NewReader(privateKey),
		HTTPClient:       transipHTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return &domain.Repository{Client: client}, nil
}

func loadConfig(cfgJSON *extapi.JSON) (solverConfig, error) {
	cfg := solverConfig{}
	if cfgJSON != nil {
		if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
			return cfg, fmt.Errorf("unmarshalling solver config: %w", err)
		}
	}

	if cfg.TTL == 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.PrivateKeySecretRef.Key == "" {
		cfg.PrivateKeySecretRef.Key = defaultPrivateKeyKey
	}
	if cfg.AccountNameKey == "" {
		cfg.AccountNameKey = defaultAccountNameKey
	}

	if cfg.PrivateKeySecretRef.Name == "" {
		return cfg, fmt.Errorf("privateKeySecretRef.name must be set")
	}
	if cfg.TTL < minTTL {
		return cfg, fmt.Errorf("ttl must be at least %d seconds, got %d", minTTL, cfg.TTL)
	}
	return cfg, nil
}

// splitFQDN returns the TransIP domain and the record name relative to it.
func splitFQDN(fqdn, zone string) (domainName, recordName string, err error) {
	domainName = strings.ToLower(strings.TrimSuffix(zone, "."))
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

	recordName, ok := strings.CutSuffix(fqdn, "."+domainName)
	if !ok || domainName == "" || recordName == "" {
		return "", "", fmt.Errorf("fqdn %q is not a name inside zone %q", fqdn, zone)
	}
	return domainName, recordName, nil
}
