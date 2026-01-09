# cert-check

A simple CLI tool to examine TLS certificate chains from remote servers.

## Installation

```bash
go install github.com/schmidtw/certcheck@latest
```

Or build from source:

```bash
git clone https://github.com/schmidtw/certcheck.git
cd certcheck
go build -o cert-check .
```

## Usage

```bash
cert-check [flags] <url>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `url` | URL or host to check (e.g., `https://example.com`, `example.com:443`) |

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | `10s` | Connection timeout |
| `--brief` | `-b` | | Show brief output (subject, issuer, validity only) |
| `--json` | `-j` | | Output in JSON format |
| `--verify` | `-v` | | Verify certificate chain (fail on invalid certs) |

### Supported Protocols

The tool automatically uses the correct default port for common TLS protocols:

- `https` - port 443
- `ldaps` - port 636
- `imaps` - port 993
- `pop3s` - port 995
- `smtps` - port 465

## Examples

Check a website's certificate chain:

```bash
cert-check example.com
```

Check with certificate verification enabled:

```bash
cert-check -v https://example.com
```

Get brief output:

```bash
cert-check -b example.com
```

Output as JSON (useful for scripting):

```bash
cert-check -j example.com
```

Check a mail server:

```bash
cert-check imaps://mail.example.com
```

### Sample Output

```
Certificate chain for example.com:443
============================================================

[0] LEAF CERTIFICATE
------------------------------------------------------------
Subject:         CN=example.com,O=Example Inc,L=San Francisco,ST=California,C=US
Issuer:          CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US

Serial Number:   1234567890
Version:         3

Not Before:      2024-01-01T00:00:00Z
Not After:       2025-01-01T23:59:59Z
Status:          Valid (180 days remaining)

Signature Algo:  SHA256-RSA
Public Key Algo: RSA
Is CA:           No

DNS Names (SANs):
  - example.com
  - www.example.com

Key Usage:
  - Digital Signature
  - Key Encipherment

Extended Key Usage:
  - Server Authentication
  - Client Authentication
```

## License

Apache-2.0
