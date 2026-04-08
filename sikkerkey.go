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
	"time"
)

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
