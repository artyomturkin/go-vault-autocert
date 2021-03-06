# Hashicorp Vault Automatic Certificates

[![Go Report Card](https://goreportcard.com/badge/github.com/artyomturkin/go-vault-autocert)](https://goreportcard.com/report/github.com/artyomturkin/go-vault-autocert)

Go package to automatically create and refresh tls.Config certificates using Hashicorp Vault PKI backend

## Usage example

```go
package main

import (
	"context"
	"crypto/tls"

	"github.com/artyomturkin/go-vault-autocert"
)

func main() {
	// Create and configure Vault PKI Provider config
	cfg := vac.VaultPKIConfig{
		Token:         "example-token",
		Role:          "example",
		CN:            "example.org",
		AdvertisedIPs: []string{"127.0.0.1", "192.168.1.1"},
	}

	// Create provider from config and context
	ctx := context.Background()
	pr, _ := vac.NewVaultPKIProvider(ctx, cfg)

	// Bind provider to tls.Config
	config := &tls.Config{}
	pr.BindTLSConfig(config)

	// Start tls listener with provided config
	ln, _ := tls.Listen("tcp", ":443", config)
	defer ln.Close()
}

```