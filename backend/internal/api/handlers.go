package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/sctg-development/stepca-ui/backend/internal/db"
	"github.com/sctg-development/stepca-ui/backend/internal/step"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handlers struct {
	db              *db.Database
	stepClient      *step.StepClient
	acmeProvisioner string
	proxy           ProxyAuth
	cookieSecure    bool
	syncFn          func() error // nil when the cert-manager sync is disabled
	throttle        *loginThrottle
}

// NewHandlers wires the handlers; acmeProvisioner is only used to display
// the ACME directory URL on the settings page.
func NewHandlers(database *db.Database, stepClient *step.StepClient, acmeProvisioner string, proxy ProxyAuth, cookieSecure bool, syncFn func() error) *Handlers {
	return &Handlers{
		db:              database,
		stepClient:      stepClient,
		acmeProvisioner: acmeProvisioner,
		proxy:           proxy,
		cookieSecure:    cookieSecure,
		syncFn:          syncFn,
		throttle:        newLoginThrottle(),
	}
}

type IssueRequest struct {
	CN           string   `json:"cn" binding:"required"`
	SANs         []string `json:"sans"`
	NotAfterDays int      `json:"not_after_days" binding:"required"`
	Profile      string   `json:"profile"`
	Format       string   `json:"format"` // pem, pfx
	PFXPassword  string   `json:"pfx_password,omitempty"`
}

type SignCSRRequest struct {
	Profile      string `json:"profile"`
	CSRPEM       string `json:"csr_pem" binding:"required"`
	NotAfterDays int    `json:"not_after_days" binding:"required"`
}

type CertResponse struct {
	ID          string    `json:"id"`
	CN          string    `json:"cn"`
	SANs        []string  `json:"sans"`
	Serial      string    `json:"serial"`
	NotAfter    time.Time `json:"not_after"`
	Status      string    `json:"status"`
	KeyStrategy string    `json:"key_strategy"`
	Owner       string    `json:"owner"`
	Profile     string    `json:"profile"`
	Source      string    `json:"source"`
	ExternalRef string    `json:"external_ref,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// effectiveStatus reports "expired" for an active certificate whose
// notAfter has passed, without waiting for a background job to flip it.
func effectiveStatus(cert *db.Certificate) string {
	if cert.Status == "active" && !cert.NotAfter.IsZero() && cert.NotAfter.Before(time.Now()) {
		return "expired"
	}
	return cert.Status
}

func toResponse(cert *db.Certificate) CertResponse {
	var sans []string
	_ = json.Unmarshal([]byte(cert.SANs), &sans)
	return CertResponse{
		ID:          cert.ID,
		CN:          cert.CN,
		SANs:        sans,
		Serial:      cert.Serial,
		NotAfter:    cert.NotAfter,
		Status:      effectiveStatus(cert),
		KeyStrategy: cert.KeyStrategy,
		Owner:       cert.OwnerUser,
		Profile:     cert.Profile,
		Source:      cert.Source,
		ExternalRef: cert.ExternalRef,
		CreatedAt:   cert.CreatedAt,
		UpdatedAt:   cert.UpdatedAt,
	}
}

type DownloadResponse struct {
	Data     []byte `json:"data"`
	Filename string `json:"filename"`
	MimeType string `json:"mime_type"`
}

// IssueCertificate issues a new certificate
func (h *Handlers) IssueCertificate(c *gin.Context) {
	var req IssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	profile, err := h.stepClient.Profile(req.Profile)
	if err == nil {
		err = profile.CheckDays(req.NotAfterDays)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate certificate using step CLI
	bundle, err := h.stepClient.IssueCertificate(profile, req.CN, req.SANs, req.NotAfterDays)
	if err != nil {
		log.Printf("IssueCertificate failed for CN=%s: %v", req.CN, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to issue certificate: %v", err)})
		return
	}

	// Generate unique ID for the certificate
	certID := uuid.New().String()

	// Store certificate metadata in database
	who := actorName(c)
	sansJSON, _ := json.Marshal(req.SANs)
	cert := &db.Certificate{
		ID:          certID,
		CN:          req.CN,
		SANs:        string(sansJSON),
		Serial:      bundle.Serial,
		NotAfter:    bundle.NotAfter,
		Status:      "active",
		KeyStrategy: "server",
		StorageRef:  "ephemeral",
		Profile:     profile.Name,
		Source:      "ui",
		OwnerUser:   who,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.db.CreateCertificate(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store certificate metadata"})
		return
	}

	// Log audit event
	auditEvent := &db.AuditEvent{
		CertID:    certID,
		Who:       who,
		Action:    "issued",
		Details:   fmt.Sprintf("profile: %s, CN: %s, SANs: %v, %d d", profile.Name, req.CN, req.SANs, req.NotAfterDays),
		Timestamp: time.Now(),
	}
	h.db.LogAuditEvent(auditEvent)

	// Create download bundle
	downloadData, err := h.stepClient.CreateDownloadBundle(bundle, req.Format, req.PFXPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create download bundle"})
		return
	}

	// Return certificate info and download data
	response := toResponse(cert)

	c.JSON(http.StatusOK, gin.H{
		"certificate": response,
		"download": gin.H{
			"data":      downloadData,
			"filename":  fmt.Sprintf("%s-cert-bundle.zip", req.CN),
			"mime_type": "application/zip",
		},
	})
}

// SignCSR signs a certificate signing request
func (h *Handlers) SignCSR(c *gin.Context) {
	var req SignCSRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	profile, err := h.stepClient.Profile(req.Profile)
	if err == nil {
		err = profile.CheckDays(req.NotAfterDays)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Sign CSR using step CLI
	bundle, err := h.stepClient.SignCSR(profile, req.CSRPEM, req.NotAfterDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to sign CSR: %v", err)})
		return
	}

	// Generate unique ID for the certificate
	certID := uuid.New().String()

	// CN and SANs come from the CSR itself (parsed and signature-verified in
	// StepClient.SignCSR) rather than being hardcoded as "unknown".
	cn := bundle.CN
	sans := bundle.SANs

	// Store certificate metadata in database
	who := actorName(c)
	sansJSON, _ := json.Marshal(sans)
	cert := &db.Certificate{
		ID:          certID,
		CN:          cn,
		SANs:        string(sansJSON),
		Serial:      bundle.Serial,
		NotAfter:    bundle.NotAfter,
		Status:      "active",
		KeyStrategy: "csr",
		StorageRef:  "ephemeral",
		Profile:     profile.Name,
		Source:      "ui",
		OwnerUser:   who,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.db.CreateCertificate(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store certificate metadata"})
		return
	}

	// Log audit event
	auditEvent := &db.AuditEvent{
		CertID:    certID,
		Who:       who,
		Action:    "signed_csr",
		Details:   fmt.Sprintf("profile: %s, CN: %s", profile.Name, cn),
		Timestamp: time.Now(),
	}
	h.db.LogAuditEvent(auditEvent)

	// Return certificate info
	response := toResponse(cert)

	c.JSON(http.StatusOK, gin.H{
		"certificate": response,
		"cert_pem":    string(bundle.CertPEM),
		"chain_pem":   string(bundle.ChainPEM),
	})
}

// ListCertificates returns a list of certificates
func (h *Handlers) ListCertificates(c *gin.Context) {
	// Parse query parameters
	limitStr := c.DefaultQuery("limit", "500")
	offsetStr := c.DefaultQuery("offset", "0")
	status := c.Query("status")
	source := c.Query("source")

	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 500
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		offset = 0
	}

	// Get certificates from database
	certs, err := h.db.ListCertificates(limit, offset, status, source)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list certificates"})
		return
	}

	responses := make([]CertResponse, 0, len(certs))
	for i := range certs {
		responses = append(responses, toResponse(&certs[i]))
	}

	c.JSON(http.StatusOK, gin.H{"certificates": responses})
}

// GetCertificate returns a specific certificate
func (h *Handlers) GetCertificate(c *gin.Context) {
	certID := c.Param("id")

	cert, err := h.db.GetCertificate(certID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	response := toResponse(cert)

	c.JSON(http.StatusOK, gin.H{"certificate": response})
}

// RenewCertificate renews a certificate
func (h *Handlers) RenewCertificate(c *gin.Context) {
	certID := c.Param("id")

	// Get existing certificate
	cert, err := h.db.GetCertificate(certID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	if cert.Source != "ui" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only certificates issued from this UI can be renewed here"})
		return
	}
	profile, err := h.stepClient.Profile(cert.Profile)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parse SANs
	var sans []string
	json.Unmarshal([]byte(cert.SANs), &sans)

	// Renewing means issuing a brand new certificate (new key pair, new
	// serial) with the same CN/SANs -- step-ca certificates are immutable
	// once issued, so there's no operation that extends an existing one's
	// expiry in place. That new cert/key only exists in memory at this
	// point (IssueCertificate's temp files are already gone by the time it
	// returns), so it MUST be handed back in this response now or it's
	// lost forever -- there is no later endpoint that can recover it.
	bundle, err := h.stepClient.IssueCertificate(profile, cert.CN, sans, profile.DefaultDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to renew certificate: %v", err)})
		return
	}

	// Update certificate in database. The old serial number now belongs to
	// a different, still-valid certificate that this record no longer
	// represents -- if Serial isn't updated too, revoking "this" cert
	// later would revoke the previous (now-superseded) one instead of the
	// new one actually in use.
	cert.Serial = bundle.Serial
	cert.NotAfter = bundle.NotAfter
	cert.Status = "active"
	cert.UpdatedAt = time.Now()
	if err := h.db.UpdateCertificate(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update certificate"})
		return
	}

	// Log audit event. OwnerUser on the certificate record itself is left
	// as whoever originally issued it -- Who here is about who performed
	// this particular renew action, which can be a different account.
	auditEvent := &db.AuditEvent{
		CertID:    certID,
		Who:       actorName(c),
		Action:    "renewed",
		Details:   fmt.Sprintf("CN: %s, new serial: %s", cert.CN, bundle.Serial),
		Timestamp: time.Now(),
	}
	h.db.LogAuditEvent(auditEvent)

	// Build the same PEM-format download bundle Issue returns, so the new
	// key material actually reaches the caller instead of being discarded.
	downloadData, err := h.stepClient.CreateDownloadBundle(bundle, "", "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create download bundle"})
		return
	}

	response := toResponse(cert)

	c.JSON(http.StatusOK, gin.H{
		"certificate": response,
		"download": gin.H{
			"data":      downloadData,
			"filename":  fmt.Sprintf("%s-cert-bundle.zip", cert.CN),
			"mime_type": "application/zip",
		},
	})
}

// RevokeCertificate revokes a certificate
func (h *Handlers) RevokeCertificate(c *gin.Context) {
	certID := c.Param("id")

	// Get certificate
	cert, err := h.db.GetCertificate(certID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	if cert.Serial == "" || cert.Source == "cert-manager" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this certificate is managed by cert-manager: delete its Secret (or the Certificate) instead"})
		return
	}
	profile, err := h.stepClient.Profile(cert.Profile)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Actually revoke with the CA -- this used to only flip the local status
	// flag, which meant a "revoked" certificate here was still perfectly
	// valid as far as step-ca was concerned.
	if err := h.stepClient.RevokeCertificate(profile, cert.Serial); err != nil {
		log.Printf("RevokeCertificate failed for cert %s (serial=%s): %v", certID, cert.Serial, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to revoke certificate with CA: %v", err)})
		return
	}

	cert.Status = "revoked"
	cert.UpdatedAt = time.Now()
	if err := h.db.UpdateCertificate(cert); err != nil {
		// The CA-side revoke already succeeded at this point; the cert IS
		// revoked, we just failed to record that locally. Surface this
		// distinctly so an operator doesn't think the revoke itself failed
		// and try again (which is harmless against step-ca, but confusing).
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Certificate was revoked with the CA, but failed to update local status"})
		return
	}

	// Log audit event
	auditEvent := &db.AuditEvent{
		CertID:    certID,
		Who:       actorName(c),
		Action:    "revoked",
		Details:   fmt.Sprintf("CN: %s", cert.CN),
		Timestamp: time.Now(),
	}
	h.db.LogAuditEvent(auditEvent)

	c.JSON(http.StatusOK, gin.H{"message": "Certificate revoked successfully"})
}

// GetCASettings returns CA configuration
func (h *Handlers) GetCASettings(c *gin.Context) {
	settings := gin.H{
		"ca_url":           h.stepClient.CAURL,
		"root_fingerprint": h.stepClient.CARootFingerprint,
		"acme_directories": []string{
			h.stepClient.CAURL + "/acme/" + h.acmeProvisioner + "/directory",
		},
	}

	c.JSON(http.StatusOK, settings)
}

// Health check endpoint
func (h *Handlers) Health(c *gin.Context) {
	response := map[string]interface{}{
		"status":             "healthy",
		"timestamp":          time.Now().Format(time.RFC3339),
		"ca_root_configured": h.stepClient.CARootFile != "" || h.stepClient.CARootFingerprint != "",
	}
	c.JSON(http.StatusOK, response)
}

// envOrUnknown reads a build-identity env var, falling back to "unknown"
// for images built without ./build.sh (a plain `docker compose build`
// leaves these ARGs at their Dockerfile defaults).
func envOrUnknown(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return "unknown"
}

// Version reports this build's identity (VERSION file contents, git
// commit, build timestamp), baked in as env vars at image build time by
// build.sh. Lets the frontend show "what am I actually running" without
// anyone needing to `docker inspect` the container by hand.
func (h *Handlers) Version(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version":    envOrUnknown("APP_VERSION"),
		"commit":     envOrUnknown("GIT_SHA"),
		"build_date": envOrUnknown("BUILD_DATE"),
		"go_version": runtime.Version(),
	})
}

// ListProfiles returns the issuance profiles the UI can use.
func (h *Handlers) ListProfiles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"profiles": h.stepClient.Profiles()})
}

// SyncNow triggers the cert-manager inventory sync immediately.
func (h *Handlers) SyncNow(c *gin.Context) {
	if h.syncFn == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cert-manager sync is not enabled"})
		return
	}
	if err := h.syncFn(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "synced"})
}

type ImportRequest struct {
	PEM string `json:"pem" binding:"required"`
}

// ImportCertificate records already-issued certificates (leaf certificates
// of a PEM bundle) so they show up in the inventory and its expiry
// monitoring. The CA's own certificates (CA:TRUE) are skipped.
func (h *Handlers) ImportCertificate(c *gin.Context) {
	var req ImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	who := actorName(c)
	rest := []byte(req.PEM)
	var imported []CertResponse
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		x, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid certificate: " + err.Error()})
			return
		}
		if x.IsCA {
			continue
		}
		serial := x.SerialNumber.String()
		if existing, err := h.db.FindBySerial(serial); err == nil && existing.ID != "" {
			continue
		}
		sans := append([]string{}, x.DNSNames...)
		for _, ip := range x.IPAddresses {
			sans = append(sans, ip.String())
		}
		sansJSON, _ := json.Marshal(sans)
		cert := &db.Certificate{
			ID:          uuid.New().String(),
			CN:          x.Subject.CommonName,
			SANs:        string(sansJSON),
			Serial:      serial,
			NotAfter:    x.NotAfter,
			Status:      "active",
			KeyStrategy: "external",
			StorageRef:  "none",
			Source:      "import",
			OwnerUser:   who,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		if cert.CN == "" && len(x.DNSNames) > 0 {
			cert.CN = x.DNSNames[0]
		}
		if err := h.db.CreateCertificate(cert); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store certificate metadata"})
			return
		}
		_ = h.db.LogAuditEvent(&db.AuditEvent{CertID: cert.ID, Who: who, Action: "imported",
			Details: fmt.Sprintf("CN: %s, serial: %s", cert.CN, serial), Timestamp: time.Now()})
		imported = append(imported, toResponse(cert))
	}
	if len(imported) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no new leaf certificate found in the PEM"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"certificates": imported})
}
