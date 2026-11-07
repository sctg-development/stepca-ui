// Package k8s mirrors cert-manager Certificates issued by step-ca into the
// UI inventory (read-only). It talks to the Kubernetes API with the pod's
// service account over plain HTTPS: only `get/list certificates` is needed,
// no client-go and no access to Secrets.
package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sctg-development/stepca-ui/backend/internal/db"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

type Syncer struct {
	db     *db.Database
	issuer string
	base   string
	client *http.Client
}

type certList struct {
	Items []struct {
		Metadata struct {
			Name              string    `json:"name"`
			Namespace         string    `json:"namespace"`
			CreationTimestamp time.Time `json:"creationTimestamp"`
		} `json:"metadata"`
		Spec struct {
			CommonName  string   `json:"commonName"`
			DNSNames    []string `json:"dnsNames"`
			IPAddresses []string `json:"ipAddresses"`
			IssuerRef   struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"issuerRef"`
		} `json:"spec"`
		Status struct {
			NotAfter *time.Time `json:"notAfter"`
		} `json:"status"`
	} `json:"items"`
}

// NewInCluster builds a Syncer from the pod's service account.
func NewInCluster(database *db.Database, issuerName string) (*Syncer, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not running in a cluster (KUBERNETES_SERVICE_HOST unset)")
	}
	caPEM, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &Syncer{
		db:     database,
		issuer: issuerName,
		base:   "https://" + net.JoinHostPort(host, port),
		client: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
	}, nil
}

func (s *Syncer) list() (*certList, error) {
	// the projected token rotates: read it on every call
	tok, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, s.base+"/apis/cert-manager.io/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kubernetes API: %s: %.200s", resp.Status, body)
	}
	var l certList
	if err := json.Unmarshal(body, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Sync replaces the cert-manager records of the inventory with the current
// Certificates whose issuerRef is the step-ca issuer.
func (s *Syncer) Sync() error {
	l, err := s.list()
	if err != nil {
		return err
	}
	var keep []string
	for _, it := range l.Items {
		if it.Spec.IssuerRef.Name != s.issuer || it.Status.NotAfter == nil {
			continue
		}
		id := "cm-" + it.Metadata.Namespace + "." + it.Metadata.Name
		sans := append(append([]string{}, it.Spec.DNSNames...), it.Spec.IPAddresses...)
		sansJSON, _ := json.Marshal(sans)
		cn := it.Spec.CommonName
		if cn == "" && len(it.Spec.DNSNames) > 0 {
			cn = it.Spec.DNSNames[0]
		}
		if cn == "" {
			cn = it.Metadata.Name
		}
		ref := it.Metadata.Namespace + "/" + it.Metadata.Name
		if err := s.db.SaveExternal(&db.Certificate{
			ID: id, CN: cn, SANs: string(sansJSON), NotAfter: *it.Status.NotAfter,
			Status: "active", KeyStrategy: "cert-manager", StorageRef: "secret",
			OwnerUser: ref, Profile: it.Spec.IssuerRef.Name, Source: "cert-manager", ExternalRef: ref,
			CreatedAt: it.Metadata.CreationTimestamp, UpdatedAt: time.Now(),
		}); err != nil {
			return err
		}
		keep = append(keep, id)
	}
	return s.db.DeleteSourceNotIn("cert-manager", keep)
}
