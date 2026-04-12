# SikkerKey Go SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/SikkerKeyOfficial/sikkerkey-go.svg)](https://pkg.go.dev/github.com/SikkerKeyOfficial/sikkerkey-go)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)

The official Go SDK for [SikkerKey](https://sikkerkey.com). Read-only access to secrets in a SikkerKey vault using Ed25519 machine authentication. Zero external dependencies - standard library only.

## Installation

```bash
go get github.com/SikkerKeyOfficial/sikkerkey-go@latest
```

## How It Works

The SDK reads an `identity.json` file from the local filesystem. This file is created during machine bootstrap and contains the machine ID, vault ID, API URL, and path to the Ed25519 private key. Every API request is signed with the private key — no API keys, no tokens, no sessions.

Default identity location: `~/.sikkerkey/vaults/<vault-id>/identity.json`

Override with the `SIKKERKEY_IDENTITY` environment variable or pass a direct path to `New()`.

## Quick Start

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

    secret, err := sk.GetSecret("sk_stripe_key")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(secret)
}
```

## Client Creation

```go
// Explicit vault ID
sk, err := sikkerkey.New("vault_abc123")

// Direct path to identity.json
sk, err := sikkerkey.New("/etc/sikkerkey/vaults/vault_abc123/identity.json")

// Auto-detect: uses SIKKERKEY_IDENTITY env, or finds the single vault on disk
sk, err := sikkerkey.NewAutoDetect()
```

Auto-detection fails with a clear error if multiple vaults are registered and no vault is specified.

## Reading Secrets

```go
// Single-value secret
value, err := sk.GetSecret("sk_api_key")

// Structured secret — all fields as map[string]string
fields, err := sk.GetFields("sk_db_credentials")
host := fields["host"]
password := fields["password"]

// Structured secret — single field
password, err := sk.GetField("sk_db_credentials", "password")
```

`GetFields` parses the secret value as JSON. Returns an error if the secret is not a structured secret.

## Listing Secrets

```go
// All secrets this machine can access
secrets, err := sk.ListSecrets()
for _, s := range secrets {
    fmt.Printf("%s  %s\n", s.ID, s.Name)
}

// Secrets in a specific project
secrets, err := sk.ListSecretsByProject("proj_production")
```

Each `SecretListItem` has `ID`, `Name`, `FieldNames` (nil for single-value secrets), and `ProjectID`.

## Exporting

```go
// Export all secrets as env-style key-value pairs
env, err := sk.Export("")

// Export secrets from a specific project
env, err := sk.Export("proj_production")

for key, value := range env {
    fmt.Printf("%s=%s\n", key, value)
}
```

Secret names are converted to uppercase environment variable format: `Database Credentials` becomes `DATABASE_CREDENTIALS`. Structured secret fields are flattened: `DATABASE_CREDENTIALS_HOST`, `DATABASE_CREDENTIALS_PASSWORD`.

## Watching for Changes

Watch secrets for real-time updates. When a secret is rotated, updated, or deleted, the callback fires with the new value. Polling happens on a background goroutine - your application is never blocked.

```go
sk.Watch("sk_db_password", func(event sikkerkey.WatchEvent) {
    switch event.Status {
    case sikkerkey.WatchStatusChanged:
        fmt.Printf("New value: %s\n", event.Value)
        // Structured secrets include parsed fields
        fmt.Printf("Fields: %v\n", event.Fields)
    case sikkerkey.WatchStatusDeleted:
        fmt.Println("Secret was deleted")
    case sikkerkey.WatchStatusAccessDenied:
        fmt.Println("Access revoked")
    case sikkerkey.WatchStatusError:
        fmt.Printf("Error: %s\n", event.Error)
    }
})
```

### Practical Example

```go
// Auto-rotate database credentials
sk.Watch("sk_db_credentials", func(event sikkerkey.WatchEvent) {
    if event.Status == sikkerkey.WatchStatusChanged {
        db.Reconfigure(event.Fields["username"], event.Fields["password"])
    }
})
```

### Poll Interval

The default poll interval is 15 seconds. The server enforces a minimum of 10 seconds.

```go
sk.SetPollInterval(30) // seconds
```

### Stop Watching

```go
// Stop watching a specific secret
sk.Unwatch("sk_db_password")

// Stop all watches and shut down polling
sk.Close()
```

## Machine Info

```go
sk.MachineID()    // "550e8400-e29b-41d4-a716-446655440000"
sk.MachineName()  // "api-server-1"
sk.VaultID()      // "vault_abc123"
sk.APIURL()       // "https://api.sikkerkey.com"
```

## Listing Vaults

```go
// All vault IDs registered on this machine
vaults := sikkerkey.ListVaults()
// ["vault_abc123", "vault_def456"]
```

## Error Handling

All errors are prefixed with `sikkerkey:` and include context:

- `sikkerkey: authentication failed` — invalid signature or machine not approved
- `sikkerkey: access denied` — machine doesn't have access to this secret
- `sikkerkey: not found` — secret doesn't exist
- `sikkerkey: server sealed` — server needs to be unsealed
- `sikkerkey: rate limited` — too many requests
- `sikkerkey: no identity found` — identity.json not found at the expected path

Network errors and 429/503 responses are retried up to 3 times with exponential backoff (1s, 2s, 4s).

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SIKKERKEY_IDENTITY` | Path to `identity.json` — overrides vault-based lookup |
| `SIKKERKEY_HOME` | Base directory for config (default: `~/.sikkerkey`) |
| `SIKKERKEY_VAULT` | Not used by the SDK directly — use `New("vault_id")` instead |

## Authentication

Every request includes four headers signed with Ed25519:

- `X-Machine-Id` — machine UUID
- `X-Timestamp` — Unix timestamp (±5 minute window)
- `X-Nonce` — random base64 nonce (replay protection)
- `X-Signature` — Ed25519 signature of `method:path:timestamp:nonce:bodyHash`

The private key is read from the PEM file referenced in `identity.json`. It never leaves the machine. HTTPS is enforced for all non-localhost connections.

## Documentation

- [SDK Overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [Go SDK Reference](https://docs.sikkerkey.com/docs/sdk/go)
- [Machine Authentication](https://docs.sikkerkey.com/docs/machines/signatures)
- [Ed25519 Signatures](https://docs.sikkerkey.com/docs/machines/signatures)

## License

MIT - see [LICENSE](LICENSE) for details.
