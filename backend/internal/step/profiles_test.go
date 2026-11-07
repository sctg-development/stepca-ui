package step

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadProfiles(t *testing.T) {
	dir := t.TempDir()
	good := write(t, dir, "p.yaml", `profiles:
  - name: ike
    provisioner: jwk-ike
    keyFile: /k/ike.json
    keyType: RSA
    keySize: 2048
    maxDays: 365
  - name: mtls
    label: mTLS clients
    provisioner: jwk-mtls
    keyFile: /k/mtls.json
    defaultDays: 400
    maxDays: 100
`)
	ps, err := LoadProfiles(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Label != "ike" || ps[0].DefaultDays != 90 {
		t.Fatalf("defaults not applied: %+v", ps[0])
	}
	if ps[1].DefaultDays != 100 {
		t.Fatalf("defaultDays must be capped by maxDays, got %d", ps[1].DefaultDays)
	}
	if err := ps[1].CheckDays(101); err == nil {
		t.Fatal("101 d must exceed maxDays 100")
	}
	if err := ps[1].CheckDays(100); err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string]string{
		"empty":     "profiles: []\n",
		"nocreds":   "profiles:\n  - {name: a, provisioner: p}\n",
		"noprov":    "profiles:\n  - {name: a, keyFile: /k}\n",
		"duplicate": "profiles:\n  - {name: a, provisioner: p, keyFile: /k}\n  - {name: a, provisioner: p, keyFile: /k}\n",
	} {
		if _, err := LoadProfiles(write(t, dir, name+".yaml", body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestProfileLookup(t *testing.T) {
	s := NewStepClient("https://ca", "", "", []Profile{{Name: "a"}, {Name: "b"}})
	if p, _ := s.Profile(""); p.Name != "a" {
		t.Fatal("empty name must select the first profile")
	}
	if _, err := s.Profile("zzz"); err == nil {
		t.Fatal("unknown profile must fail")
	}
}
