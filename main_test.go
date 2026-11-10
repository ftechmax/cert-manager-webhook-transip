package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/transip/gotransip/v6/domain"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSplitFQDN(t *testing.T) {
	tests := []struct {
		fqdn, zone           string
		wantDomain, wantName string
		wantErr              bool
	}{
		{fqdn: "_acme-challenge.example.nl.", zone: "example.nl.", wantDomain: "example.nl", wantName: "_acme-challenge"},
		{fqdn: "_acme-challenge.www.example.nl.", zone: "example.nl.", wantDomain: "example.nl", wantName: "_acme-challenge.www"},
		{fqdn: "_acme-challenge.example.nl", zone: "example.nl", wantDomain: "example.nl", wantName: "_acme-challenge"},
		{fqdn: "_acme-challenge.Example.NL.", zone: "example.nl.", wantDomain: "example.nl", wantName: "_acme-challenge"},
		{fqdn: "_acme-challenge.other.nl.", zone: "example.nl.", wantErr: true},
		{fqdn: "_acme-challenge.notexample.nl.", zone: "example.nl.", wantErr: true},
		{fqdn: "example.nl.", zone: "example.nl.", wantErr: true},
		{fqdn: "_acme-challenge.example.nl.", zone: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.fqdn+" in "+tt.zone, func(t *testing.T) {
			gotDomain, gotName, err := splitFQDN(tt.fqdn, tt.zone)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got (%q, %q)", gotDomain, gotName)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotDomain != tt.wantDomain || gotName != tt.wantName {
				t.Errorf("got (%q, %q), want (%q, %q)", gotDomain, gotName, tt.wantDomain, tt.wantName)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		json    string // empty means no config at all
		want    transipDNSProviderConfig
		wantErr string
	}{
		{
			name: "defaults",
			json: `{"privateKeySecretRef":{"name":"creds"}}`,
			want: transipDNSProviderConfig{
				TTL:                 300,
				PrivateKeySecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "creds"}, Key: "privateKey"},
				AccountNameKey:      "accountName",
			},
		},
		{
			name: "all fields set",
			json: `{"ttl":3600,"privateKeySecretRef":{"name":"creds","key":"pem"},"accountNameKey":"user"}`,
			want: transipDNSProviderConfig{
				TTL:                 3600,
				PrivateKeySecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "creds"}, Key: "pem"},
				AccountNameKey:      "user",
			},
		},
		{name: "no config", wantErr: "privateKeySecretRef.name must be set"},
		{name: "missing secret name", json: `{"ttl":300}`, wantErr: "privateKeySecretRef.name must be set"},
		{name: "ttl too low", json: `{"ttl":30,"privateKeySecretRef":{"name":"creds"}}`, wantErr: "ttl must be at least 60"},
		{name: "negative ttl", json: `{"ttl":-1,"privateKeySecretRef":{"name":"creds"}}`, wantErr: "ttl must be at least 60"},
		{name: "invalid json", json: `{`, wantErr: "unmarshalling solver config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw *extapi.JSON
			if tt.json != "" {
				raw = &extapi.JSON{Raw: []byte(tt.json)}
			}
			got, err := loadConfig(raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got error %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

type fakeRepo struct {
	entries map[string][]domain.DNSEntry
	failAdd bool
}

func (r *fakeRepo) GetDNSEntries(domainName string) ([]domain.DNSEntry, error) {
	entries, ok := r.entries[domainName]
	if !ok {
		return nil, fmt.Errorf("domain %s not found", domainName)
	}
	return append([]domain.DNSEntry(nil), entries...), nil
}

func (r *fakeRepo) AddDNSEntry(domainName string, entry domain.DNSEntry) error {
	if r.failAdd {
		return errors.New("api error")
	}
	r.entries[domainName] = append(r.entries[domainName], entry)
	return nil
}

func (r *fakeRepo) RemoveDNSEntry(domainName string, entry domain.DNSEntry) error {
	entries := r.entries[domainName]
	for i, e := range entries {
		if e == entry {
			r.entries[domainName] = append(entries[:i], entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("entry %+v not found", entry)
}

func (r *fakeRepo) txtRecords(domainName, name string) []string {
	var keys []string
	for _, e := range r.entries[domainName] {
		if e.Type == "TXT" && e.Name == name {
			keys = append(keys, e.Content)
		}
	}
	return keys
}

const testNamespace = "cert-manager"

func newTestSolver(t *testing.T, secretData map[string][]byte) (*transipDNSProviderSolver, *fakeRepo) {
	t.Helper()
	repo := &fakeRepo{entries: map[string][]domain.DNSEntry{
		"example.nl": {{Name: "www", Expire: 3600, Type: "A", Content: "192.0.2.1"}},
	}}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "transip-credentials", Namespace: testNamespace},
		Data:       secretData,
	}
	s := &transipDNSProviderSolver{
		client: fake.NewClientset(secret),
		newRepo: func(accountName string, privateKey []byte) (dnsRepository, error) {
			if accountName != "myaccount" || string(privateKey) != "PEM" {
				t.Errorf("unexpected credentials: %q / %q", accountName, privateKey)
			}
			return repo, nil
		},
	}
	return s, repo
}

var validSecretData = map[string][]byte{"privateKey": []byte("PEM"), "accountName": []byte("myaccount")}

func newChallenge(key, config string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		ResolvedFQDN:      "_acme-challenge.example.nl.",
		ResolvedZone:      "example.nl.",
		ResourceNamespace: testNamespace,
		Key:               key,
		Config:            &extapi.JSON{Raw: []byte(config)},
	}
}

const defaultTestConfig = `{"privateKeySecretRef":{"name":"transip-credentials"}}`

func TestPresentAndCleanUp(t *testing.T) {
	s, repo := newTestSolver(t, validSecretData)
	// Apex and wildcard challenges share the same TXT record name.
	apex := newChallenge("key-apex", defaultTestConfig)
	wildcard := newChallenge("key-wildcard", defaultTestConfig)

	if err := s.Present(apex); err != nil {
		t.Fatalf("Present: %v", err)
	}
	got := repo.entries["example.nl"][1]
	want := domain.DNSEntry{Name: "_acme-challenge", Expire: 300, Type: "TXT", Content: "key-apex"}
	if got != want {
		t.Errorf("created entry %+v, want %+v", got, want)
	}

	if err := s.Present(apex); err != nil {
		t.Fatalf("Present again: %v", err)
	}
	if err := s.Present(wildcard); err != nil {
		t.Fatalf("Present wildcard: %v", err)
	}
	assertKeys(t, repo, "key-apex", "key-wildcard")

	if err := s.CleanUp(apex); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	assertKeys(t, repo, "key-wildcard")

	if err := s.CleanUp(apex); err != nil {
		t.Fatalf("CleanUp again: %v", err)
	}
	if err := s.CleanUp(wildcard); err != nil {
		t.Fatalf("CleanUp wildcard: %v", err)
	}
	assertKeys(t, repo)

	if n := len(repo.entries["example.nl"]); n != 1 {
		t.Errorf("expected only the original A record to remain, got %d entries", n)
	}
}

func assertKeys(t *testing.T, repo *fakeRepo, want ...string) {
	t.Helper()
	got := repo.txtRecords("example.nl", "_acme-challenge")
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("TXT records = %v, want %v", got, want)
	}
}

func TestPresentUsesConfig(t *testing.T) {
	s, repo := newTestSolver(t, map[string][]byte{"pem": []byte("PEM"), "user": []byte("myaccount")})
	ch := newChallenge("key", `{"ttl":60,"privateKeySecretRef":{"name":"transip-credentials","key":"pem"},"accountNameKey":"user"}`)

	if err := s.Present(ch); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := repo.entries["example.nl"][1].Expire; got != 60 {
		t.Errorf("TTL = %d, want 60", got)
	}
}

func TestCleanUpUsesStoredEntry(t *testing.T) {
	s, repo := newTestSolver(t, validSecretData)
	repo.entries["example.nl"] = append(repo.entries["example.nl"], domain.DNSEntry{
		Name: "_ACME-CHALLENGE", Expire: 3600, Type: "TXT", Content: "key",
	})

	if err := s.CleanUp(newChallenge("key", defaultTestConfig)); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if n := len(repo.entries["example.nl"]); n != 1 {
		t.Errorf("expected only the original A record to remain, got %d entries", n)
	}
}

func TestPresentErrors(t *testing.T) {
	tests := []struct {
		name       string
		secretData map[string][]byte
		challenge  func() *v1alpha1.ChallengeRequest
		failAdd    bool
		wantErr    string
	}{
		{
			name:       "missing secret",
			secretData: validSecretData,
			challenge:  func() *v1alpha1.ChallengeRequest { return newChallenge("k", `{"privateKeySecretRef":{"name":"nope"}}`) },
			wantErr:    "reading secret cert-manager/nope",
		},
		{
			name:       "missing private key",
			secretData: map[string][]byte{"accountName": []byte("myaccount")},
			challenge:  func() *v1alpha1.ChallengeRequest { return newChallenge("k", defaultTestConfig) },
			wantErr:    `key "privateKey" not found`,
		},
		{
			name:       "missing account name",
			secretData: map[string][]byte{"privateKey": []byte("PEM")},
			challenge:  func() *v1alpha1.ChallengeRequest { return newChallenge("k", defaultTestConfig) },
			wantErr:    `key "accountName" not found`,
		},
		{
			name:       "unknown domain",
			secretData: validSecretData,
			challenge: func() *v1alpha1.ChallengeRequest {
				ch := newChallenge("k", defaultTestConfig)
				ch.ResolvedFQDN, ch.ResolvedZone = "_acme-challenge.other.nl.", "other.nl."
				return ch
			},
			wantErr: "listing dns entries for other.nl",
		},
		{
			name:       "fqdn outside zone",
			secretData: validSecretData,
			challenge: func() *v1alpha1.ChallengeRequest {
				ch := newChallenge("k", defaultTestConfig)
				ch.ResolvedFQDN = "_acme-challenge.other.nl."
				return ch
			},
			wantErr: "is not a name inside zone",
		},
		{
			name:       "api error on add",
			secretData: validSecretData,
			challenge:  func() *v1alpha1.ChallengeRequest { return newChallenge("k", defaultTestConfig) },
			failAdd:    true,
			wantErr:    "adding dns entry",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, repo := newTestSolver(t, tt.secretData)
			repo.failAdd = tt.failAdd
			err := s.Present(tt.challenge())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got error %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}
