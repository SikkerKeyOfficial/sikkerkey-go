package sikkerkey

// On-disk fallback secret cache — the Go SDK port of the .skc format defined by
// the SikkerKey CLI. Files are byte-compatible with the CLI and the other SDKs:
// same key derivation, AES-256-GCM sealing, AAD, envelope, and path, so a cache
// written by one is readable by all.
//
// Strictly opt-in (Client.EnableCache) and inert until then: nothing here runs
// unless the client constructs a secretCache, which happens only when caching is on.
//
//	key   = HKDF-SHA256(ikm = ed25519_seed, salt = vaultId, info = "sikkerkey-cache-v1")  → 32 bytes
//	entry = AES-256-GCM(key, nonce = random 12B, plaintext = {name,value,fieldNames} JSON,
//	                    aad = "sikkerkey-cache-v1\0{vaultId}\0{machineId}\0{secretId}\0{cachedAt}")

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

const (
	cacheFormatVersion = 1
	cacheKDFInfo       = "sikkerkey-cache-v1"
	cacheFileExt       = ".skc"
)

// Guards the on-disk filename against traversal; real secret ids are sk_<alnum>.
var safeCacheSecretID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// cacheDir is ~/.sikkerkey/vaults/{vaultId}/cache, beside the identity it belongs to.
func cacheDir(vaultID string) string {
	return filepath.Join(getBaseDir(), "vaults", vaultID, "cache")
}

type cacheResult struct {
	SecretID   string
	Name       string
	Value      string
	FieldNames *string
	CachedAt   time.Time
}

type secretCache struct {
	vaultID   string
	machineID string
	key       []byte
}

func newSecretCache(vaultID, machineID string, seed []byte) *secretCache {
	return &secretCache{vaultID: vaultID, machineID: machineID, key: deriveCacheKey(seed, vaultID)}
}

type cachePayload struct {
	Name       string  `json:"name,omitempty"`
	Value      string  `json:"value"`
	FieldNames *string `json:"fieldNames,omitempty"`
}

type cacheEnvelope struct {
	Version  int    `json:"v"`
	Nonce    string `json:"nonce"`
	CT       string `json:"ct"`
	CachedAt int64  `json:"cachedAt"`
}

func (c *secretCache) store(secretID, name, value string, fieldNames *string) error {
	if !safeCacheSecretID.MatchString(secretID) {
		return fmt.Errorf("sikkerkey: refusing to cache unsafe secret id %q", secretID)
	}
	cachedAt := time.Now().Unix()
	pt, err := json.Marshal(cachePayload{Name: name, Value: value, FieldNames: fieldNames})
	if err != nil {
		return err
	}
	nonce, ct, err := cacheSeal(c.key, pt, c.aad(secretID, cachedAt))
	if err != nil {
		return err
	}
	env, err := json.Marshal(cacheEnvelope{
		Version:  cacheFormatVersion,
		Nonce:    base64.StdEncoding.EncodeToString(nonce),
		CT:       base64.StdEncoding.EncodeToString(ct),
		CachedAt: cachedAt,
	})
	if err != nil {
		return err
	}
	return cacheWriteAtomic(c.filePath(secretID), env)
}

// load returns the cached entry, or (nil, nil) on a miss. A decrypt failure
// (tampered, or from a different identity) is a real error.
func (c *secretCache) load(secretID string) (*cacheResult, error) {
	if !safeCacheSecretID.MatchString(secretID) {
		return nil, nil
	}
	data, err := os.ReadFile(c.filePath(secretID))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c.decode(secretID, data)
}

func (c *secretCache) decode(secretID string, data []byte) (*cacheResult, error) {
	var env cacheEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("sikkerkey: corrupt cache entry for %s: %w", secretID, err)
	}
	if env.Version != cacheFormatVersion {
		return nil, nil // a newer format wrote this; treat as a miss
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, err
	}
	pt, err := cacheOpen(c.key, nonce, ct, c.aad(secretID, env.CachedAt))
	if err != nil {
		return nil, fmt.Errorf("sikkerkey: cache entry for %s failed to decrypt (wrong identity or tampered)", secretID)
	}
	var p cachePayload
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, err
	}
	return &cacheResult{
		SecretID:   secretID,
		Name:       p.Name,
		Value:      p.Value,
		FieldNames: p.FieldNames,
		CachedAt:   time.Unix(env.CachedAt, 0),
	}, nil
}

func (c *secretCache) filePath(secretID string) string {
	return filepath.Join(cacheDir(c.vaultID), secretID+cacheFileExt)
}

// aad binds an entry to its context: domain || vault || machine || secret || timestamp.
func (c *secretCache) aad(secretID string, cachedAt int64) []byte {
	return []byte(cacheKDFInfo + "\x00" + c.vaultID + "\x00" + c.machineID + "\x00" + secretID + "\x00" + strconv.FormatInt(cachedAt, 10))
}

// ── Crypto ──

func deriveCacheKey(seed []byte, vaultID string) []byte {
	return hkdfSHA256Cache(seed, []byte(vaultID), []byte(cacheKDFInfo), 32)
}

func cacheSeal(key, plaintext, aad []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func cacheOpen(key, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("bad nonce length")
	}
	return gcm.Open(nil, nonce, ct, aad)
}

// hkdfSHA256Cache is RFC 5869 HKDF over HMAC-SHA256, hand-rolled to keep the SDK
// dependency-free.
func hkdfSHA256Cache(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)
	var out, t []byte
	for i := byte(1); len(out) < length; i++ {
		exp := hmac.New(sha256.New, prk)
		exp.Write(t)
		exp.Write(info)
		exp.Write([]byte{i})
		t = exp.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// cacheWriteAtomic writes via a temp file + rename so a reader never sees a
// half-written entry and concurrent writers never corrupt each other.
func cacheWriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".skc-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
