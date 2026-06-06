// Package sikkerkey provides a read-only client for accessing secrets in a SikkerKey vault.
//
// Quick start:
//
//	sk, err := sikkerkey.New("vault_abc123")
//	secret, err := sk.GetSecret("sk_a1b2c3d4e5")
//
// Structured secrets:
//
//	fields, err := sk.GetFields("sk_db_prod")
//	host := fields["host"]
package sikkerkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultAPIURL = "https://api.sikkerkey.com"

func getBaseDir() string {
	if env := os.Getenv("SIKKERKEY_HOME"); env != "" {
		return env
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/tmp"
	}
	return filepath.Join(home, ".sikkerkey")
}

func getVaultsDir() string { return filepath.Join(getBaseDir(), "vaults") }

// Client is a SikkerKey SDK client bound to a specific vault.
type Client struct {
	identity   identity
	privateKey ed25519.PrivateKey

	watchMu       sync.Mutex
	watchers      map[string]func(WatchEvent)
	pollInterval  time.Duration
	pollStop      chan struct{}
	pollRunning   bool
}

type identity struct {
	MachineID      string `json:"machineId"`
	MachineName    string `json:"machineName"`
	VaultID        string `json:"vaultId"`
	APIURL         string `json:"apiUrl"`
	PrivateKeyPath string `json:"privateKeyPath"`
}

// New creates a SikkerKey client for the given vault ID.
// Pass a vault ID (e.g. "vault_abc123"), a path to identity.json, or "" to auto-detect.
func New(vaultOrPath string) (*Client, error) {
	var ptr *string
	if vaultOrPath != "" {
		ptr = &vaultOrPath
	}
	idFile, err := resolveIdentity(ptr)
	if err != nil {
		return nil, err
	}
	return loadFromFile(idFile)
}

// NewAutoDetect creates a SikkerKey client by auto-detecting the vault.
func NewAutoDetect() (*Client, error) {
	idFile, err := resolveIdentity(nil)
	if err != nil {
		return nil, err
	}
	return loadFromFile(idFile)
}

// BootstrapOptions configures an in-memory bootstrap.
type BootstrapOptions struct {
	// Hostname recorded on the enrolled machine. If empty, $HOSTNAME, then "serverless".
	// Must match the enrollment token's hostname pattern if one is set.
	Hostname string
	// Name requested for the machine. Overridden when the enrollment token defines a name pattern.
	Name string
}

// BootstrapInMemory enrolls an ephemeral machine in memory and returns a ready client,
// for serverless and other read-only-filesystem environments that have no identity on disk.
//
// It generates an Ed25519 keypair in memory, registers an ephemeral machine using the
// enrollment token, and returns a client whose identity lives only in process memory —
// nothing is written to disk. Enrollment happens once, here. The returned client then
// behaves exactly like one created with New: it signs each read with the in-memory key.
//
// The ephemeral machine lives for the lifetime set on the enrollment token; reading after
// it expires returns an authentication error, so size the token's machine lifetime to the
// workload. The common path is to read secrets at startup and hold the values.
func BootstrapInMemory(vaultID, token string, opts ...BootstrapOptions) (*Client, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("sikkerkey: BootstrapInMemory requires a vault ID")
	}
	if token == "" {
		return nil, fmt.Errorf("sikkerkey: BootstrapInMemory requires an enrollment token")
	}

	var opt BootstrapOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// SikkerKey is a managed service; the API URL is fixed. The env override is for local dev only.
	apiURL := defaultAPIURL
	if env := os.Getenv("SIKKERKEY_API_URL"); env != "" {
		apiURL = env
	}
	if !strings.HasPrefix(apiURL, "https://") && !strings.HasPrefix(apiURL, "http://localhost") {
		return nil, fmt.Errorf("sikkerkey: API URL must use HTTPS: %s. Use http://localhost only for local development", apiURL)
	}
	apiURL = strings.TrimRight(apiURL, "/")

	// Generate the keypair in memory. The private key never leaves this process.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to generate keypair: %w", err)
	}
	// Server expects the raw 32-byte public key as standard base64 (44 chars).
	publicKeyB64 := base64.StdEncoding.EncodeToString(pub)

	hostname := opt.Hostname
	if hostname == "" {
		hostname = os.Getenv("HOSTNAME")
	}
	if hostname == "" {
		hostname = "serverless"
	}

	resp, err := enrollRegister(apiURL, vaultID, token, publicKeyB64, hostname, opt.Name)
	if err != nil {
		return nil, err
	}

	// Enrollment ran against the backend (apiURL); runtime reads go to the
	// retrieval plane the backend hands back. Fall back to the enroll URL only
	// if an older endpoint omits it.
	readURL := resp.APIURL
	if readURL == "" {
		readURL = apiURL
	}

	return &Client{
		identity: identity{
			MachineID:   resp.MachineID,
			MachineName: resp.MachineName,
			VaultID:     resp.VaultID,
			APIURL:      readURL,
		},
		privateKey: priv,
	}, nil
}

type enrollResponse struct {
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
	VaultID     string `json:"vaultId"`
	ExpiresAt   int64  `json:"expiresAt"`
	// Retrieval-plane base URL (the machine-service); stored as the identity's read URL.
	APIURL string `json:"apiUrl"`
}

func enrollRegister(apiURL, vaultID, token, publicKey, hostname, name string) (*enrollResponse, error) {
	reqBody := map[string]string{
		"token":     token,
		"publicKey": publicKey,
		"hostname":  hostname,
	}
	if name != "" {
		reqBody["name"] = name
	}
	payload, _ := json.Marshal(reqBody)

	url := apiURL + "/v1/" + vaultID + "/enroll/register"
	req, err := http.NewRequest("POST", url, strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to create enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sikkerkey: enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to read enrollment response: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var er enrollResponse
		if err := json.Unmarshal(respBody, &er); err != nil {
			return nil, fmt.Errorf("sikkerkey: failed to parse enrollment response: %w", err)
		}
		if er.MachineID == "" || er.VaultID == "" {
			return nil, fmt.Errorf("sikkerkey: malformed enrollment response")
		}
		return &er, nil
	}

	var errResp struct {
		Error string `json:"error"`
	}
	errMsg := string(respBody)
	if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
		errMsg = errResp.Error
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("sikkerkey: authentication failed: %s", errMsg)
	case http.StatusForbidden:
		return nil, fmt.Errorf("sikkerkey: access denied: %s", errMsg)
	case http.StatusNotFound:
		return nil, fmt.Errorf("sikkerkey: not found: %s", errMsg)
	case http.StatusConflict:
		return nil, fmt.Errorf("sikkerkey: conflict: %s", errMsg)
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("sikkerkey: rate limited: %s", errMsg)
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("sikkerkey: server sealed: %s", errMsg)
	default:
		return nil, fmt.Errorf("sikkerkey: enrollment failed (%d): %s", resp.StatusCode, errMsg)
	}
}

// MachineID returns the machine's UUID.
func (c *Client) MachineID() string { return c.identity.MachineID }

// MachineName returns the machine's registered name.
func (c *Client) MachineName() string { return c.identity.MachineName }

// VaultID returns the vault ID.
func (c *Client) VaultID() string { return c.identity.VaultID }

// APIURL returns the SikkerKey API URL.
func (c *Client) APIURL() string { return c.identity.APIURL }

// ── Read ──

// GetSecret fetches a secret by ID and returns the decrypted value.
func (c *Client) GetSecret(secretID string) (string, error) {
	body, err := c.request("GET", "/v1/secret/"+secretID, nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	var resp struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("sikkerkey: failed to parse response: %w", err)
	}
	return resp.Value, nil
}

// GetFields fetches a structured secret and returns its fields as a map.
func (c *Client) GetFields(secretID string) (map[string]string, error) {
	raw, err := c.GetSecret(secretID)
	if err != nil {
		return nil, err
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return nil, fmt.Errorf("sikkerkey: secret %s is not a structured secret", secretID)
	}
	return fields, nil
}

// GetField fetches a single field from a structured secret.
func (c *Client) GetField(secretID, field string) (string, error) {
	fields, err := c.GetFields(secretID)
	if err != nil {
		return "", err
	}
	val, ok := fields[field]
	if !ok {
		return "", fmt.Errorf("sikkerkey: field '%s' not found in secret %s", field, secretID)
	}
	return val, nil
}

// ── List ──

// SecretListItem is metadata for a secret returned by list operations.
type SecretListItem struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	FieldNames *string `json:"fieldNames"`
	ProjectID  *string `json:"projectId"`
}

// ListSecrets returns all secrets this machine has access to.
func (c *Client) ListSecrets() ([]SecretListItem, error) {
	body, err := c.request("GET", "/v1/secrets", nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Secrets []SecretListItem `json:"secrets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to parse response: %w", err)
	}
	return resp.Secrets, nil
}

// ListSecretsByProject returns secrets in a specific project.
func (c *Client) ListSecretsByProject(projectID string) ([]SecretListItem, error) {
	payload, _ := json.Marshal(map[string]string{"projectId": projectID})
	body, err := c.request("POST", "/v1/secrets/list", payload, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Secrets []SecretListItem `json:"secrets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to parse response: %w", err)
	}
	return resp.Secrets, nil
}

// ── Export ──

// Export returns all accessible secrets as a flat key-value map (single round trip).
// Structured secrets are flattened: SECRET_NAME_FIELD_NAME.
// Pass projectID="" to export all projects.
func (c *Client) Export(projectID string) (map[string]string, error) {
	var payload []byte
	if projectID != "" {
		payload, _ = json.Marshal(map[string]string{"projectId": projectID})
	}
	body, err := c.request("POST", "/v1/secrets/export", payload, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Secrets []struct {
			ID         string  `json:"id"`
			Name       string  `json:"name"`
			Value      string  `json:"value"`
			FieldNames *string `json:"fieldNames"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to parse export response: %w", err)
	}

	result := make(map[string]string)
	for _, s := range resp.Secrets {
		envName := toEnvName(s.Name)
		if s.FieldNames != nil {
			var fields map[string]string
			if json.Unmarshal([]byte(s.Value), &fields) == nil && len(fields) > 0 {
				for k, v := range fields {
					result[envName+"_"+toEnvName(k)] = v
				}
				continue
			}
		}
		result[envName] = s.Value
	}
	return result, nil
}

// ── List Vaults ──

// ListVaults returns the vault IDs registered on this machine.
func ListVaults() []string {
	entries, err := os.ReadDir(getVaultsDir())
	if err != nil {
		return nil
	}
	var vaults []string
	for _, e := range entries {
		if e.IsDir() {
			idPath := filepath.Join(getVaultsDir(), e.Name(), "identity.json")
			if _, err := os.Stat(idPath); err == nil {
				vaults = append(vaults, e.Name())
			}
		}
	}
	return vaults
}

// ── Watch ──

// WatchStatus represents the status of a watched secret change.
type WatchStatus string

const (
	// WatchStatusChanged indicates the secret value was updated.
	WatchStatusChanged WatchStatus = "changed"
	// WatchStatusDeleted indicates the secret was deleted.
	WatchStatusDeleted WatchStatus = "deleted"
	// WatchStatusAccessDenied indicates access to the secret was revoked.
	WatchStatusAccessDenied WatchStatus = "access_denied"
	// WatchStatusError indicates an error occurred while polling or fetching.
	WatchStatusError WatchStatus = "error"
)

// WatchEvent is delivered to a Watch callback when a secret changes.
type WatchEvent struct {
	SecretID string            // The secret that changed
	Status   WatchStatus       // What happened
	Value    string            // New decrypted value for CHANGED, empty otherwise
	Fields   map[string]string // Parsed fields for structured secrets, nil for simple
	Error    string            // Error message for ERROR status
}

// Watch registers a callback that fires whenever the given secret changes.
// The poll goroutine is started lazily on the first call.
func (c *Client) Watch(secretID string, callback func(WatchEvent)) {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()

	if c.watchers == nil {
		c.watchers = make(map[string]func(WatchEvent))
	}
	if c.pollInterval == 0 {
		c.pollInterval = 15 * time.Second
	}

	c.watchers[secretID] = callback

	if !c.pollRunning {
		c.pollStop = make(chan struct{})
		c.pollRunning = true
		go c.pollLoop()
	}
}

// Unwatch removes the callback for a secret. If no watches remain, polling stops.
func (c *Client) Unwatch(secretID string) {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()

	delete(c.watchers, secretID)

	if len(c.watchers) == 0 && c.pollRunning {
		close(c.pollStop)
		c.pollRunning = false
	}
}

// SetPollInterval sets the polling interval in seconds. Minimum 10 seconds.
func (c *Client) SetPollInterval(seconds int) {
	if seconds < 10 {
		seconds = 10
	}
	c.watchMu.Lock()
	c.pollInterval = time.Duration(seconds) * time.Second
	c.watchMu.Unlock()
}

// Close stops the poll goroutine and clears all watches.
func (c *Client) Close() {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()

	if c.pollRunning {
		close(c.pollStop)
		c.pollRunning = false
	}
	c.watchers = nil
}

// pollLoop is the background goroutine that polls for secret changes.
func (c *Client) pollLoop() {
	c.watchMu.Lock()
	interval := c.pollInterval
	c.watchMu.Unlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.pollStop:
			return
		case <-ticker.C:
			c.pollOnce()

			// Check if interval changed and reset ticker if so
			c.watchMu.Lock()
			newInterval := c.pollInterval
			c.watchMu.Unlock()
			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
			}
		}
	}
}

// pollOnce performs a single poll cycle.
func (c *Client) pollOnce() {
	c.watchMu.Lock()
	ids := make([]string, 0, len(c.watchers))
	for id := range c.watchers {
		ids = append(ids, id)
	}
	c.watchMu.Unlock()

	if len(ids) == 0 {
		return
	}

	payload, _ := json.Marshal(map[string][]string{"watch": ids})
	body, err := c.request("POST", "/v1/secrets/poll", payload, http.StatusOK)
	if err != nil {
		// Fire error event on all watchers
		c.watchMu.Lock()
		callbacks := make(map[string]func(WatchEvent), len(c.watchers))
		for id, cb := range c.watchers {
			callbacks[id] = cb
		}
		c.watchMu.Unlock()

		for id, cb := range callbacks {
			cb(WatchEvent{
				SecretID: id,
				Status:   WatchStatusError,
				Error:    err.Error(),
			})
		}
		return
	}

	var resp struct {
		Changes map[string]struct {
			Status string `json:"status"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return
	}

	for id, change := range resp.Changes {
		status := WatchStatus(change.Status)

		c.watchMu.Lock()
		cb, ok := c.watchers[id]
		c.watchMu.Unlock()
		if !ok {
			continue
		}

		switch status {
		case WatchStatusChanged:
			value, fetchErr := c.GetSecret(id)
			if fetchErr != nil {
				cb(WatchEvent{
					SecretID: id,
					Status:   WatchStatusError,
					Error:    fetchErr.Error(),
				})
				continue
			}

			var fields map[string]string
			if json.Unmarshal([]byte(value), &fields) != nil {
				fields = nil
			}

			cb(WatchEvent{
				SecretID: id,
				Status:   WatchStatusChanged,
				Value:    value,
				Fields:   fields,
			})

		case WatchStatusDeleted, WatchStatusAccessDenied:
			cb(WatchEvent{
				SecretID: id,
				Status:   status,
			})

			// Remove from watchers - access is gone
			c.watchMu.Lock()
			delete(c.watchers, id)
			if len(c.watchers) == 0 && c.pollRunning {
				close(c.pollStop)
				c.pollRunning = false
			}
			c.watchMu.Unlock()

		default:
			cb(WatchEvent{
				SecretID: id,
				Status:   WatchStatusError,
				Error:    fmt.Sprintf("unknown poll status: %s", change.Status),
			})
		}
	}
}

// ── Internal ──

var retryableCodes = map[int]bool{429: true, 503: true}
var backoffMs = []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
const maxRetries = 3

func (c *Client) request(method, path string, body []byte, expectStatus int) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			idx := attempt - 1
			if idx >= len(backoffMs) {
				idx = len(backoffMs) - 1
			}
			time.Sleep(backoffMs[idx])
		}

		// Fresh nonce + timestamp per attempt (replay protection)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return nil, fmt.Errorf("sikkerkey: failed to generate nonce: %w", err)
		}
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)

		bodyStr := ""
		if body != nil {
			bodyStr = string(body)
		}
		bodyHash := sha256Hex(bodyStr)

		signPayload := fmt.Sprintf("%s:%s:%s:%s:%s", method, path, timestamp, nonce, bodyHash)
		signature := base64.StdEncoding.EncodeToString(ed25519.Sign(c.privateKey, []byte(signPayload)))

		url := c.identity.APIURL + path
		var reqBody io.Reader
		if body != nil {
			reqBody = strings.NewReader(string(body))
		}

		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			return nil, fmt.Errorf("sikkerkey: failed to create request: %w", err)
		}
		req.Header.Set("X-Machine-Id", c.identity.MachineID)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Nonce", nonce)
		req.Header.Set("X-Signature", signature)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		httpClient := &http.Client{Timeout: 15 * time.Second}
		resp, err := httpClient.Do(req)
		if err != nil {
			// Network error — retry
			lastErr = fmt.Errorf("sikkerkey: request failed: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("sikkerkey: failed to read response: %w", err)
			continue
		}

		if resp.StatusCode == expectStatus {
			return respBody, nil
		}

		var errResp struct {
			Error string `json:"error"`
		}
		errMsg := string(respBody)
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			errMsg = errResp.Error
		}

		if retryableCodes[resp.StatusCode] && attempt < maxRetries {
			lastErr = fmt.Errorf("sikkerkey: %s (HTTP %d)", errMsg, resp.StatusCode)
			continue
		}

		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("sikkerkey: authentication failed: %s", errMsg)
		case http.StatusForbidden:
			return nil, fmt.Errorf("sikkerkey: access denied: %s", errMsg)
		case http.StatusNotFound:
			return nil, fmt.Errorf("sikkerkey: not found: %s", errMsg)
		case http.StatusConflict:
			return nil, fmt.Errorf("sikkerkey: conflict: %s", errMsg)
		case http.StatusTooManyRequests:
			return nil, fmt.Errorf("sikkerkey: rate limited: %s", errMsg)
		case http.StatusServiceUnavailable:
			return nil, fmt.Errorf("sikkerkey: server sealed: %s", errMsg)
		default:
			return nil, fmt.Errorf("sikkerkey: request failed (%d): %s", resp.StatusCode, errMsg)
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("sikkerkey: request failed after %d retries", maxRetries)
}

func resolveIdentity(vaultOrPath *string) (string, error) {
	if vaultOrPath != nil {
		v := *vaultOrPath
		if strings.HasPrefix(v, "/") || strings.Contains(v, "identity.json") {
			return v, nil
		}

		vaultID := v
		if !strings.HasPrefix(vaultID, "vault_") {
			vaultID = "vault_" + vaultID
		}
		path := filepath.Join(getVaultsDir(), vaultID, "identity.json")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("sikkerkey: no identity found for vault '%s'. Expected: %s. Run the bootstrap command first", vaultID, path)
	}

	if envPath := os.Getenv("SIKKERKEY_IDENTITY"); envPath != "" {
		return envPath, nil
	}

	entries, err := os.ReadDir(getVaultsDir())
	if err == nil {
		var found []string
		for _, e := range entries {
			if e.IsDir() {
				idPath := filepath.Join(getVaultsDir(), e.Name(), "identity.json")
				if _, err := os.Stat(idPath); err == nil {
					found = append(found, idPath)
				}
			}
		}
		if len(found) == 1 {
			return found[0], nil
		}
		if len(found) > 1 {
			var names []string
			for _, f := range found {
				names = append(names, filepath.Base(filepath.Dir(f)))
			}
			return "", fmt.Errorf("sikkerkey: multiple vaults registered: %s. Specify which vault to use", strings.Join(names, ", "))
		}
	}

	return "", fmt.Errorf("sikkerkey: no identity found. Run the bootstrap command first. Checked: %s/*/identity.json", getVaultsDir())
}

func loadFromFile(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to read identity file %s: %w", path, err)
	}

	var id identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to parse identity file: %w", err)
	}

	if !strings.HasPrefix(id.APIURL, "https://") && !strings.HasPrefix(id.APIURL, "http://localhost") {
		return nil, fmt.Errorf("sikkerkey: API URL must use HTTPS: %s. Use http://localhost only for local development", id.APIURL)
	}

	keyData, err := os.ReadFile(id.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to read private key %s: %w", id.PrivateKeyPath, err)
	}

	privateKey, err := loadEd25519PrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("sikkerkey: failed to load private key: %w", err)
	}

	return &Client{
		identity:   id,
		privateKey: privateKey,
	}, nil
}

func loadEd25519PrivateKey(pemData []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return edKey, nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func toEnvName(name string) string {
	result := strings.ToUpper(name)
	out := make([]byte, 0, len(result))
	prevUnderscore := false
	for _, c := range []byte(result) {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			out = append(out, c)
			prevUnderscore = false
		} else if !prevUnderscore {
			out = append(out, '_')
			prevUnderscore = true
		}
	}
	return strings.Trim(string(out), "_")
}
