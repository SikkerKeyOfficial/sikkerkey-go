# SikkerKey Go SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/SikkerKeyOfficial/sikkerkey-go.svg)](https://pkg.go.dev/github.com/SikkerKeyOfficial/sikkerkey-go)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)

Use the official SikkerKey Go SDK to give a Go application read access to the secrets its machine is authorized to use.

The SDK can:

- Read standard and structured secrets.
- List the secrets available to a machine.
- Export accessible secrets as application-friendly key/value pairs.
- Monitor selected secrets for changes.
- Use persistent machine identities or memory-only ephemeral identities.
- Keep an optional encrypted fallback cache for temporary service or network outages.

After the client is initialized, every secret request is authenticated with the machine's Ed25519 identity. The SDK requires Go 1.22 or newer and uses only the Go standard library.

## Install the SDK

```bash
go get github.com/SikkerKeyOfficial/sikkerkey-go@latest
```

## Read your first secret

```go
package main

import (
	"fmt"
	"log"

	sikkerkey "github.com/SikkerKeyOfficial/sikkerkey-go"
)

func main() {
	sk, err := sikkerkey.New("vault_abc123")
	if err != nil {
		log.Fatal(err)
	}

	apiKey, err := sk.GetSecret("sk_stripe_key")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(apiKey)
}
```

The SDK loads the machine identity from:

```text
~/.sikkerkey/vaults/vault_abc123/identity.json
```

It signs the request with the machine's Ed25519 private key and returns the secret value as a `string`. Your application's access remains limited by the machine's configured access.

## Create a client

```go
// Select a registered vault.
sk, err := sikkerkey.New("vault_abc123")

// Load a specific identity file.
sk, err := sikkerkey.New(
	"/etc/sikkerkey/vaults/vault_abc123/identity.json",
)

// Use SIKKERKEY_IDENTITY or auto-select the only registered vault.
sk, err := sikkerkey.NewAutoDetect()
```

Passing an empty string to `New` also enables auto-detection.

When auto-detecting, the SDK checks `SIKKERKEY_IDENTITY` first. If that variable is not set, it uses the only registered vault under `~/.sikkerkey/vaults/`.

If more than one vault is registered, select one explicitly. Missing identities, unreadable keys, invalid identity files, and ambiguous vault selection are returned as errors.

The `vault_` prefix is added when a vault ID is supplied without it.

### Use a different identity directory

```bash
export SIKKERKEY_HOME=/var/lib/sikkerkey
```

The SDK will look under:

```text
/var/lib/sikkerkey/vaults/<vault-id>/identity.json
```

## Use an ephemeral identity

`BootstrapInMemory` is designed for short-lived or read-only environments where an identity should not be stored on disk.

```go
sk, err := sikkerkey.BootstrapInMemory(
	os.Getenv("SIKKERKEY_VAULT_ID"),
	os.Getenv("SIKKERKEY_ENROLLMENT_TOKEN"),
)
if err != nil {
	log.Fatal(err)
}

databaseURL, err := sk.GetSecret("sk_db_prod")
```

During bootstrap, the SDK:

1. Generates an Ed25519 key pair in memory.
2. Uses the enrollment token to register an ephemeral machine.
3. Keeps the private key inside the running process.
4. Returns a client ready to read the secrets allowed by the token's access policy.

Nothing is written to disk by `BootstrapInMemory`. The private key disappears when the process exits.

The enrollment token registers the machine; it does not read secrets itself. The resulting machine remains subject to the token's permitted scope, use limit, hostname rules, and machine lifetime. Reads fail with an authentication error after the machine expires.

### Set the machine hostname and name

```go
sk, err := sikkerkey.BootstrapInMemory(
	vaultID,
	enrollmentToken,
	sikkerkey.BootstrapOptions{
		Hostname: "worker-1",
		Name:     "invoice-runner",
	},
)
```

`Hostname` defaults to the `HOSTNAME` environment variable and then to `serverless`. A name pattern configured on the enrollment token takes precedence over `Name`.

For reliable ephemeral deployments:

- Set a machine lifetime long enough for the workload to finish.
- Allow enough token uses for expected cold starts and concurrency.
- Use a unique name pattern such as `worker-{uuid8}`.
- Ensure the vault's IP allowlist permits the workload's outbound address when an allowlist is enabled.

Each active ephemeral machine uses a machine slot until it expires.

## Read secrets

### Standard secrets

```go
apiKey, err := sk.GetSecret("sk_stripe_prod")
```

### Structured secrets

```go
database, err := sk.GetFields("sk_db_prod")
if err != nil {
	log.Fatal(err)
}

host := database["host"]
username := database["username"]
password := database["password"]
```

`GetFields` expects a JSON object whose values can be decoded as strings. It returns an error when the secret has another structure.

Use `GetField` when the application needs one field:

```go
password, err := sk.GetField("sk_db_prod", "password")
```

A missing field is returned as an error.

## Discover accessible secrets

```go
secrets, err := sk.ListSecrets()
if err != nil {
	log.Fatal(err)
}

for _, secret := range secrets {
	fmt.Printf("%s: %s\n", secret.ID, secret.Name)
}
```

Limit the result to one project:

```go
productionSecrets, err :=
	sk.ListSecretsByProject("proj_production")
```

Each `SecretListItem` contains:

| Field | Type | Meaning |
|---|---|---|
| `ID` | `string` | Secret ID used by read methods |
| `Name` | `string` | Display name |
| `FieldNames` | `*string` | Optional structured-field metadata |
| `ProjectID` | `*string` | Owning project, when present |

Listing returns metadata, not secret values.

## Export secrets for application configuration

`Export` retrieves accessible values in one request:

```go
configuration, err := sk.Export("")
```

Pass a project ID to limit the export:

```go
productionConfiguration, err :=
	sk.Export("proj_production")
```

The returned `map[string]string` uses uppercase environment-style names. Structured secrets are expanded into one entry per field:

```text
API_KEY
DB_CREDENTIALS_HOST
DB_CREDENTIALS_USERNAME
DB_CREDENTIALS_PASSWORD
```

## Continue reads during temporary outages

The fallback cache is disabled by default:

```go
sk, err := sikkerkey.New("vault_abc123")
if err != nil {
	log.Fatal(err)
}
sk.EnableCache()
```

After it is enabled, successful `GetSecret` reads are stored under:

```text
~/.sikkerkey/vaults/<vault-id>/cache/
```

`GetFields` and `GetField` use `GetSecret`, so their successful reads are cached too. Cache writes are best-effort and cannot turn a successful live read into a failure.

The SDK can return a cached value after a transport failure or HTTP `502`, `503`, `504`, `520` through `527`, or `530`.

Authentication failures, revoked access, missing secrets, rate limits, and other authoritative responses are never replaced by cached values.

Entries use AES-256-GCM with a key derived from the machine's Ed25519 identity and vault ID. Tampered entries and entries belonging to another identity are rejected. The `.skc` format is compatible with other SikkerKey SDKs and the SikkerKey CLI.

### Limit cache age and observe fallback use

```go
sk.EnableCache(sikkerkey.CacheOptions{
	MaxAge: time.Hour,
	OnFallback: func(secretID string, cachedAt time.Time) {
		log.Printf(
			"using cached value for %s from %s",
			secretID,
			cachedAt,
		)
	},
})
```

A zero `MaxAge` means no automatic expiry. The callback is optional; the SDK otherwise serves fallback values silently.

The cache is intended for a host with a persistent, protected identity directory, not a memory-only identity that disappears with the process.

## Monitor secrets for changes

```go
sk.Watch("sk_db_credentials", func(event sikkerkey.WatchEvent) {
	switch event.Status {
	case sikkerkey.WatchStatusChanged:
		fmt.Printf("%s changed\n", event.SecretID)
		username := event.Fields["username"]
		password := event.Fields["password"]
		_ = username
		_ = password

	case sikkerkey.WatchStatusDeleted:
		fmt.Printf("%s was deleted\n", event.SecretID)

	case sikkerkey.WatchStatusAccessDenied:
		fmt.Printf("access to %s was removed\n", event.SecretID)

	case sikkerkey.WatchStatusError:
		log.Printf("watch failed: %s", event.Error)
	}
})
```

The SDK polls from a background goroutine every 15 seconds by default. Callbacks run on that polling goroutine, so hand slow or blocking work to another goroutine or worker queue.

For changed secrets, `Value` contains the complete new value and `Fields` contains parsed structured fields when available. Deleted and inaccessible secrets are automatically removed from the watch list. A failed poll sends an error event to each active watcher.

### Change or stop polling

```go
sk.SetPollInterval(30) // seconds; minimum 10
sk.Unwatch("sk_db_credentials")
sk.Close()
```

`Close` stops polling and clears all callbacks. It does not prevent later secret reads.

## Work with more than one vault

```go
production, err := sikkerkey.New("vault_production")
staging, err := sikkerkey.New("vault_staging")

productionKey, err :=
	production.GetSecret("sk_api_key")
stagingKey, err :=
	staging.GetSecret("sk_api_key")
```

List locally registered vault IDs:

```go
vaultIDs := sikkerkey.ListVaults()
```

## Inspect the active machine

```go
fmt.Println(sk.MachineID())
fmt.Println(sk.MachineName())
fmt.Println(sk.VaultID())
fmt.Println(sk.APIURL())
```

| Method | Meaning |
|---|---|
| `MachineID()` | Machine UUID assigned by SikkerKey |
| `MachineName()` | Machine name assigned during provisioning or enrollment |
| `VaultID()` | Vault associated with the identity |
| `APIURL()` | Service endpoint stored in the identity |

## Handle errors

HTTP and transport failures use `*sikkerkey.APIError`:

```go
value, err := sk.GetSecret("sk_example")
if err != nil {
	var apiErr *sikkerkey.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 0:
			log.Printf("network failure: %s", apiErr.Message)
		case http.StatusUnauthorized:
			log.Printf("authentication failed")
		case http.StatusForbidden:
			log.Printf("access denied")
		case http.StatusNotFound:
			log.Printf("secret not found")
		default:
			log.Printf(
				"SikkerKey returned HTTP %d",
				apiErr.StatusCode,
			)
		}
	} else {
		log.Printf("configuration or parsing error: %s", err)
	}
}
_ = value
```

`APIError.StatusCode` is `0` for DNS, connection, TLS, timeout, and other transport failures. Configuration and local parsing errors are ordinary Go errors with a `sikkerkey:` prefix and contextual messages.

### Retries and timeout

Authenticated secret requests retry transport failures and HTTP `429` or `503` responses up to three times, waiting 1, 2, and 4 seconds. Every attempt uses a fresh timestamp and nonce.

Each request has a 15-second timeout. Other HTTP responses are returned immediately as an `APIError`.

## Feature-to-API reference

| What you want to do | SDK API | Result |
|---|---|---|
| Create a client from a vault or path | `New(vaultOrPath)` | `(*Client, error)` |
| Auto-detect an identity | `NewAutoDetect()` | `(*Client, error)` |
| Create an ephemeral client | `BootstrapInMemory(vaultID, token, opts...)` | `(*Client, error)` |
| List locally registered vaults | `ListVaults()` | `[]string` |
| Enable outage fallback | `EnableCache(opts...)` | The same `*Client` |
| Read a standard secret | `GetSecret(secretID)` | `(string, error)` |
| Read every structured field | `GetFields(secretID)` | `(map[string]string, error)` |
| Read one structured field | `GetField(secretID, field)` | `(string, error)` |
| List accessible secrets | `ListSecrets()` | `([]SecretListItem, error)` |
| List accessible secrets in a project | `ListSecretsByProject(projectID)` | `([]SecretListItem, error)` |
| Export accessible values | `Export(projectID)` | `(map[string]string, error)` |
| Monitor a secret | `Watch(secretID, callback)` | No return value |
| Stop monitoring one secret | `Unwatch(secretID)` | No return value |
| Set the polling interval | `SetPollInterval(seconds)` | No return value |
| Stop all monitoring | `Close()` | No return value |

## Runtime footprint

The SDK uses the Go standard library for HTTPS, JSON, Ed25519, AES-GCM, and HKDF. It has no external module dependencies.

## Documentation

- [SikkerKey documentation](https://docs.sikkerkey.com)
- [SDK overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [Go SDK reference](https://docs.sikkerkey.com/docs/sdk/go)
- [Machine authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

The SikkerKey Go SDK is available under the [MIT License](LICENSE).
