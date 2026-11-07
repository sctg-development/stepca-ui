package step

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// stepCmdTimeout bounds every shell-out to the step CLI (or openssl) so a
// hung or unreachable CA can't block a request forever. step CLI calls go
// over the network to the CA, so this needs to be generous enough for a
// slow connection but not unbounded.
const stepCmdTimeout = 30 * time.Second

// runCommand runs name with args under stepCmdTimeout and returns combined
// stdout+stderr, wrapping the error with that output on failure so callers
// keep the same diagnostics they had before.
func runCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), stepCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("%s command timed out after %s: %s", name, stepCmdTimeout, string(output))
	}
	if err != nil {
		return output, fmt.Errorf("%s command failed: %s, error: %w", name, string(output), err)
	}
	return output, nil
}

type CertBundle struct {
	CN           string
	SANs         []string
	CertPEM      []byte
	KeyPEM       []byte
	ChainPEM     []byte
	FullChainPEM []byte
	PFXData      []byte
	Serial       string
	NotAfter     time.Time
}

// extractJWTToken pulls the JWT out of `step ca token` output. The step CLI
// prints some decorative/status text before the actual token, so we look
// for the line that looks like a JWT (starts with the "ey" of a base64url
// "{" header) rather than trusting the whole output to be just the token.
func extractJWTToken(output []byte) (string, error) {
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ey") {
			return trimmed, nil
		}
	}
	return "", fmt.Errorf("failed to extract JWT token from step ca token output: %s", string(output))
}

// parseCSRSubject decodes a PEM-encoded CSR, verifies its self-signature
// (proving the requester holds the private key for the embedded public
// key), and returns the CN and DNS SANs it's actually requesting.
func parseCSRSubject(csrPEM string) (cn string, sans []string, err error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", nil, fmt.Errorf("failed to decode PEM block from CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return "", nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	return csr.Subject.CommonName, csr.DNSNames, nil
}

type StepClient struct {
	CAURL             string
	CARootFile        string
	CARootFingerprint string
	profiles          []Profile
}

func NewStepClient(caURL, caRootFile, caRootFingerprint string, profiles []Profile) *StepClient {
	return &StepClient{
		CAURL:             caURL,
		CARootFile:        caRootFile,
		CARootFingerprint: caRootFingerprint,
		profiles:          profiles,
	}
}

// Profiles lists the configured issuance profiles (credentials excluded by
// the json tags on Profile).
func (s *StepClient) Profiles() []Profile { return s.profiles }

// Profile resolves a profile by name; an empty name selects the first one.
func (s *StepClient) Profile(name string) (*Profile, error) {
	if len(s.profiles) == 0 {
		return nil, fmt.Errorf("no issuance profile configured")
	}
	if name == "" {
		return &s.profiles[0], nil
	}
	for i := range s.profiles {
		if s.profiles[i].Name == name {
			return &s.profiles[i], nil
		}
	}
	return nil, fmt.Errorf("unknown profile %q", name)
}

// CheckDays validates a requested validity against the profile limits.
func (p *Profile) CheckDays(days int) error {
	if days <= 0 {
		return fmt.Errorf("validity must be at least 1 day")
	}
	if days > p.MaxDays {
		return fmt.Errorf("validity %d d exceeds the %d d maximum of profile %q", days, p.MaxDays, p.Name)
	}
	return nil
}

// rootPath returns a file holding the CA root: the configured file, or one
// downloaded (and fingerprint-checked) into tempDir.
func (s *StepClient) rootPath(tempDir string) (string, error) {
	if s.CARootFile != "" {
		return s.CARootFile, nil
	}
	rootPath := filepath.Join(tempDir, "root.crt")
	rootArgs := []string{"ca", "root", rootPath, "--ca-url", s.CAURL}
	if s.CARootFingerprint != "" {
		rootArgs = append(rootArgs, "--fingerprint", s.CARootFingerprint)
	}
	if _, err := runCommand("step", rootArgs...); err != nil {
		return "", fmt.Errorf("failed to fetch CA root: %w", err)
	}
	return rootPath, nil
}

// token asks the step CLI for a one-time token signed with the profile's
// provisioner key. `step ca token` is also what authorizes revocation
// (revoke=true): `step ca revoke` itself takes no provisioner flags.
func (s *StepClient) token(p *Profile, tempDir, rootPath, subject string, sans []string, revoke bool) (string, error) {
	args := []string{"ca", "token", subject,
		"--ca-url", s.CAURL, "--root", rootPath, "--provisioner", p.Provisioner}
	if revoke {
		args = append(args, "--revoke")
	}
	if p.KeyFile != "" {
		args = append(args, "--key", p.KeyFile)
	}
	if p.Password != "" {
		pwFile := filepath.Join(tempDir, "password.txt")
		if err := os.WriteFile(pwFile, []byte(p.Password), 0600); err != nil {
			return "", fmt.Errorf("failed to write password file: %w", err)
		}
		args = append(args, "--password-file", pwFile)
		if p.KeyFile == "" {
			// CA-side encrypted key (provisioner added with --create)
			args = append(args, "--provisioner-password-file", pwFile)
		}
	}
	for _, san := range sans {
		args = append(args, "--san", san)
	}
	out, err := runCommand("step", args...)
	if err != nil {
		return "", fmt.Errorf("failed to generate CA token: %w", err)
	}
	return extractJWTToken(out)
}

func (s *StepClient) keyArgs(p *Profile) []string {
	var args []string
	if p.KeyType != "" {
		args = append(args, "--kty", p.KeyType)
		if p.KeySize > 0 && p.KeyType == "RSA" {
			args = append(args, "--size", fmt.Sprint(p.KeySize))
		}
	}
	return args
}

func (s *StepClient) finish(cn string, sans []string, certPath, keyPath, rootPath string) (*CertBundle, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file: %w", err)
	}
	var keyPEM []byte
	if keyPath != "" {
		if keyPEM, err = os.ReadFile(keyPath); err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
	}
	chainPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read root certificate: %w", err)
	}
	serial, notAfter, err := s.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return &CertBundle{
		CN:           cn,
		SANs:         sans,
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		ChainPEM:     chainPEM,
		FullChainPEM: append(append([]byte{}, certPEM...), chainPEM...),
		Serial:       serial,
		NotAfter:     notAfter,
	}, nil
}

func (s *StepClient) IssueCertificate(p *Profile, cn string, sans []string, notAfterDays int) (*CertBundle, error) {
	tempDir, err := os.MkdirTemp("", "step-cert-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "cert.key")

	rootPath, err := s.rootPath(tempDir)
	if err != nil {
		return nil, err
	}
	token, err := s.token(p, tempDir, rootPath, cn, sans, false)
	if err != nil {
		return nil, err
	}

	// --not-after on `ca certificate` is the certificate validity (the token
	// validity is fixed by the CA).
	args := []string{"ca", "certificate", cn, certPath, keyPath,
		"--token", token, "--ca-url", s.CAURL, "--root", rootPath,
		"--not-after", fmt.Sprintf("%dh", notAfterDays*24)}
	args = append(args, s.keyArgs(p)...)
	if _, err := runCommand("step", args...); err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}
	return s.finish(cn, sans, certPath, keyPath, rootPath)
}

func (s *StepClient) SignCSR(p *Profile, csrPEM string, notAfterDays int) (*CertBundle, error) {
	cn, sans, err := parseCSRSubject(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}
	if cn == "" {
		return nil, fmt.Errorf("invalid CSR: no common name (CN) in subject")
	}

	tempDir, err := os.MkdirTemp("", "step-csr-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	csrPath := filepath.Join(tempDir, "csr.pem")
	certPath := filepath.Join(tempDir, "cert.crt")
	if err := os.WriteFile(csrPath, []byte(csrPEM), 0600); err != nil {
		return nil, fmt.Errorf("failed to write CSR file: %w", err)
	}

	rootPath, err := s.rootPath(tempDir)
	if err != nil {
		return nil, err
	}
	// The token must carry the CSR's subject and SANs: step-ca checks them
	// against the token when signing.
	token, err := s.token(p, tempDir, rootPath, cn, sans, false)
	if err != nil {
		return nil, err
	}
	args := []string{"ca", "sign", csrPath, certPath,
		"--token", token, "--ca-url", s.CAURL, "--root", rootPath,
		"--not-after", fmt.Sprintf("%dh", notAfterDays*24)}
	if _, err := runCommand("step", args...); err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}
	return s.finish(cn, sans, certPath, "", rootPath)
}

// RevokeCertificate revokes by serial (decimal) using a revocation token.
func (s *StepClient) RevokeCertificate(p *Profile, serial string) error {
	tempDir, err := os.MkdirTemp("", "step-revoke-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	rootPath, err := s.rootPath(tempDir)
	if err != nil {
		return err
	}
	token, err := s.token(p, tempDir, rootPath, serial, nil, true)
	if err != nil {
		return fmt.Errorf("failed to generate revocation token: %w", err)
	}
	args := []string{"ca", "revoke", serial, "--token", token, "--ca-url", s.CAURL, "--root", rootPath}
	if _, err := runCommand("step", args...); err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}
	return nil
}

func (s *StepClient) CreatePFX(certPEM, keyPEM, password string) ([]byte, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "step-pfx-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "cert.key")
	pfxPath := filepath.Join(tempDir, "cert.p12")
	passwordPath := filepath.Join(tempDir, "password.txt")

	// Write certificate and key files
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}
	if err := os.WriteFile(passwordPath, []byte(password), 0600); err != nil {
		return nil, fmt.Errorf("failed to write password file: %w", err)
	}

	// Build step command
	args := []string{
		"certificate", "p12",
		pfxPath,
		certPath,
		keyPath,
		"--password-file", passwordPath,
	}

	if _, err := runCommand("step", args...); err != nil {
		return nil, fmt.Errorf("failed to create PFX bundle: %w", err)
	}

	// Read PFX file
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PFX file: %w", err)
	}

	return pfxData, nil
}

// parseCertificate reads the serial number and expiry out of a PEM
// certificate using Go's own crypto/x509 rather than shelling out to
// openssl. This is not just simpler: openssl's `-serial` output is hex,
// while step-ca's own CLI and revocation API expect the serial as a plain
// decimal integer (see e.g. the decimal serial in `step ca revoke`'s own
// docs/examples) -- so the previous openssl-based version was recording
// certificates under a serial format the CA wouldn't recognize for revoke.
func (s *StepClient) parseCertificate(certPEM []byte) (string, time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", time.Time{}, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.SerialNumber.String(), cert.NotAfter, nil
}

func (s *StepClient) CreateDownloadBundle(bundle *CertBundle, format string, pfxPassword string) ([]byte, error) {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Add certificate files
	if err := s.addFileToZip(zipWriter, "cert.pem", bundle.CertPEM); err != nil {
		return nil, err
	}
	if err := s.addFileToZip(zipWriter, "chain.pem", bundle.ChainPEM); err != nil {
		return nil, err
	}
	if err := s.addFileToZip(zipWriter, "fullchain.pem", bundle.FullChainPEM); err != nil {
		return nil, err
	}

	// Add private key if available
	if len(bundle.KeyPEM) > 0 {
		if err := s.addFileToZip(zipWriter, "privkey.pem", bundle.KeyPEM); err != nil {
			return nil, err
		}
	}

	// Add PFX if requested
	if format == "pfx" && len(bundle.KeyPEM) > 0 {
		pfxData, err := s.CreatePFX(string(bundle.CertPEM), string(bundle.KeyPEM), pfxPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to create PFX: %w", err)
		}
		if err := s.addFileToZip(zipWriter, "cert.p12", pfxData); err != nil {
			return nil, err
		}
	}

	// Add README with installation instructions
	readme := s.generateReadme(format)
	if err := s.addFileToZip(zipWriter, "README.txt", []byte(readme)); err != nil {
		return nil, err
	}

	if err := zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zip writer: %w", err)
	}

	return buf.Bytes(), nil
}

func (s *StepClient) addFileToZip(zipWriter *zip.Writer, filename string, data []byte) error {
	fileWriter, err := zipWriter.Create(filename)
	if err != nil {
		return err
	}
	_, err = fileWriter.Write(data)
	return err
}

func (s *StepClient) generateReadme(format string) string {
	readme := "# Certificate Installation Instructions\n\n"
	readme += "## Files in this bundle:\n"
	readme += "- cert.pem: Your certificate\n"
	readme += "- chain.pem: Certificate chain (intermediate CAs)\n"
	readme += "- fullchain.pem: Certificate + chain (use this for most applications)\n"
	readme += "- privkey.pem: Private key (keep this secure!)\n"

	if format == "pfx" {
		// Deliberately NOT printing pfxPassword here: it used to be written
		// in plaintext into this README, bundled in the very same zip as
		// the password-protected cert.p12 -- which defeats the point of
		// protecting the PFX with a password at all, since anyone who gets
		// the zip gets both.
		readme += "- cert.p12: PFX/PKCS#12 bundle (password: set on the issue/download form -- not stored in this bundle; check the UI or your password manager)\n"
	}

	readme += "\n## Installation Instructions\n\n"
	readme += "### Linux/Ubuntu (Nginx, Apache, etc.)\n"
	readme += "```bash\n"
	readme += "# Copy files to appropriate locations\n"
	readme += "sudo cp fullchain.pem /etc/ssl/certs/your-domain.crt\n"
	readme += "sudo cp privkey.pem /etc/ssl/private/your-domain.key\n\n"
	readme += "# For Nginx, update your server block:\n"
	readme += "# ssl_certificate /etc/ssl/certs/your-domain.crt;\n"
	readme += "# ssl_certificate_key /etc/ssl/private/your-domain.key;\n\n"
	readme += "# Reload nginx\n"
	readme += "sudo nginx -s reload\n"
	readme += "```\n\n"

	readme += "### Windows (IIS)\n"
	readme += "1. Import cert.p12 into Certificate Store\n"
	readme += "2. Use IIS Manager to bind the certificate to your site\n\n"

	readme += "### Trust the CA Root\n"
	readme += "To trust this CA on client systems:\n\n"
	readme += "**Linux/Ubuntu:**\n"
	readme += "```bash\n"
	readme += "sudo cp chain.pem /usr/local/share/ca-certificates/my-ca.crt\n"
	readme += "sudo update-ca-certificates\n"
	readme += "```\n\n"

	readme += "**Windows PowerShell:**\n"
	readme += "```powershell\n"
	readme += "Import-Certificate -FilePath chain.pem -CertStoreLocation Cert:\\LocalMachine\\Root\n"
	readme += "```\n\n"

	readme += "## Verification\n"
	readme += "```bash\n"
	readme += "# Verify certificate chain\n"
	readme += "openssl verify -CAfile chain.pem cert.pem\n\n"
	readme += "# Check certificate details\n"
	readme += "openssl x509 -in cert.pem -text -noout\n\n"
	readme += "# Test SSL connection\n"
	readme += "openssl s_client -connect your-domain:443 -showcerts\n"
	readme += "```\n"

	return readme
}
