package step

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// RootFingerprint returns the SHA-256 fingerprint (hex, as printed by
// `step certificate fingerprint`) of the first certificate of a PEM file.
func RootFingerprint(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate in %s", path)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", err
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
