package sikkerkey

import (
	"os"
	"path/filepath"
	"testing"
)

func cacheTestSeed(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func TestCacheRoundTrip(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := newSecretCache("vault_test", "m_test", cacheTestSeed(1))
	fn := "host,pass"
	if err := c.store("sk_abc", "DB Creds", `{"host":"db"}`, &fn); err != nil {
		t.Fatal(err)
	}
	r, err := c.load("sk_abc")
	if err != nil {
		t.Fatal(err)
	}
	if r == nil || r.Value != `{"host":"db"}` || r.Name != "DB Creds" || r.FieldNames == nil || *r.FieldNames != fn {
		t.Fatalf("round-trip mismatch: %+v", r)
	}
}

func TestCacheMiss(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := newSecretCache("vault_test", "m_test", cacheTestSeed(1))
	r, err := c.load("sk_missing")
	if err != nil || r != nil {
		t.Fatalf("expected miss, got (%v, %v)", r, err)
	}
}

func TestCacheWrongIdentity(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	if err := newSecretCache("vault_test", "m_test", cacheTestSeed(1)).store("sk_x", "", "v", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := newSecretCache("vault_test", "m_test", cacheTestSeed(2)).load("sk_x"); err == nil {
		t.Fatal("expected decrypt failure with a different identity")
	}
}

func TestCacheTamper(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := newSecretCache("vault_test", "m_test", cacheTestSeed(1))
	if err := c.store("sk_abc", "", "v", nil); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(cacheDir("vault_test"), "sk_abc.skc")
	data, _ := os.ReadFile(p)
	data[len(data)/2] ^= 0xFF
	os.WriteFile(p, data, 0o600)
	if _, err := c.load("sk_abc"); err == nil {
		t.Fatal("expected tampered entry to be rejected")
	}
}

// A .skc produced by the Node/CLI reference (fixed seed 0x42*32, vault_golden,
// m_golden) must decrypt here — proving byte-for-byte cross-SDK compatibility of
// the key derivation, AAD, AES-GCM sealing, and envelope.
func TestCacheGoldenVector(t *testing.T) {
	const golden = `{"v":1,"nonce":"aRft7abMsZ0ggD9K","ct":"lvUT+AOq5lb8U7/cOMnO13yWH+dJJWgyHqIBGriU7VfGT8/4LyG0olAm56U=","cachedAt":1784893492}`
	c := newSecretCache("vault_golden", "m_golden", cacheTestSeed(0x42))
	r, err := c.decode("sk_golden", []byte(golden))
	if err != nil {
		t.Fatalf("golden decode failed: %v", err)
	}
	if r == nil || r.Value != "golden-value-123" {
		t.Fatalf("golden value = %+v, want golden-value-123", r)
	}
}

func TestIsUnavailableSet(t *testing.T) {
	for _, code := range []int{0, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527, 530} {
		if !isUnavailable(&APIError{StatusCode: code}) {
			t.Errorf("status %d should be treated as unavailable", code)
		}
	}
	for _, code := range []int{200, 400, 401, 403, 404, 409, 429, 500, 501} {
		if isUnavailable(&APIError{StatusCode: code}) {
			t.Errorf("status %d must NOT be treated as unavailable", code)
		}
	}
}
