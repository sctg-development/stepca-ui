package step

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRootFingerprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	p := filepath.Join(t.TempDir(), "root.crt")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	got, err := RootFingerprint(p)
	sum := sha256.Sum256(der)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint %q err %v", got, err)
	}
	os.WriteFile(p, []byte("garbage"), 0600)
	if _, err := RootFingerprint(p); err == nil {
		t.Fatal("garbage must be refused")
	}
}
