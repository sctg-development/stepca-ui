package k8s

import "testing"

func TestIssuerSet(t *testing.T) {
	s := toSet([]string{"step-ca", "lesmuids-ca-issuer"})
	if !s["step-ca"] || !s["lesmuids-ca-issuer"] || s["letsencrypt-cloudflare"] {
		t.Fatalf("unexpected set %v", s)
	}
}
