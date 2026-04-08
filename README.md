# SikkerKey Go SDK

The official Go SDK for [SikkerKey](https://sikkerkey.com) — read secrets from your vault using Ed25519 machine authentication.

## Installation

```bash
go get github.com/SikkerKeyOfficial/sikkerkey-go@latest
```

## Prerequisites

The machine must be registered with SikkerKey via the CLI:

```bash
sikkerkey connect <vault-id>
```

The machine identity (Ed25519 keypair) is stored locally and used by the SDK for authentication. No API keys, no tokens.

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    sikkerkey "github.com/SikkerKeyOfficial/sikkerkey-go"
)

func main() {
    // Connect using a specific vault
    sk, err := sikkerkey.New("vault_abc123")
    if err != nil {
        log.Fatal(err)
    }

    // Read a secret
    apiKey, err := sk.GetSecret("sk_stripe_key")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(apiKey)
}
```

## Auto-Detection

If the machine has only one vault configured, or the `SIKKERKEY_VAULT` environment variable is set:

```go
sk, err := sikkerkey.NewAutoDetect()
```

## API

### Client Creation

```go
// Connect to a specific vault
sk, err := sikkerkey.New("vault_abc123")

// Auto-detect vault from environment or single-vault config
sk, err := sikkerkey.NewAutoDetect()
```

### Reading Secrets

```go
// Single-value secret
value, err := sk.GetSecret("sk_api_key")

// Structured secret — all fields
fields, err := sk.GetFields("sk_db_credentials")
host := fields["host"]
password := fields["password"]

// Structured secret — single field
password, err := sk.GetField("sk_db_credentials", "password")
```

### Listing Secrets

```go
// All accessible secrets
secrets, err := sk.ListSecrets()
for _, s := range secrets {
    fmt.Printf("%s: %s\n", s.ID, s.Name)
}

// Secrets in a specific project
secrets, err := sk.ListSecretsByProject("proj_abc123")
```

### Exporting

```go
// Export all secrets as a map (key=secret name, value=secret value)
env, err := sk.Export("proj_abc123")
for key, value := range env {
    fmt.Printf("%s=%s\n", key, value)
}
```

### Machine Info

```go
sk.MachineID()    // UUID
sk.MachineName()  // e.g. "api-server-1"
sk.VaultID()      // e.g. "vault_abc123"
sk.APIURL()       // e.g. "https://api.sikkerkey.com"
```

### Listing Vaults

```go
// List all configured vault IDs on this machine
vaults := sikkerkey.ListVaults()
```

## Authentication

Every request is signed with the machine's Ed25519 private key. The signature covers the HTTP method, path, timestamp, nonce, and body hash. The server verifies the signature against the machine's registered public key.

No secrets, tokens, or API keys are transmitted. The private key never leaves the machine.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SIKKERKEY_VAULT` | Override vault ID for auto-detection |
| `SIKKERKEY_HOME` | Override config directory (default: `~/.sikkerkey`) |
| `SIKKERKEY_IDENTITY` | Override path to identity file |

## Documentation

- [SDK Overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [Go SDK Reference](https://docs.sikkerkey.com/docs/sdk/go)
- [Machine Authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

Proprietary. See [sikkerkey.com/terms](https://sikkerkey.com/terms) for details.
