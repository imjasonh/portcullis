# Portcullis

**Your machine is a castle. `curl | bash` is an open gate. Portcullis drops the gate and inspects what's trying to enter.**

Portcullis is a CLI tool that interposes in shell script execution pipelines to verify trust before allowing execution. It uses Sigstore for identity and Rekor as a public transparency log for trust attestations.

## Usage

```bash
# Primary use case: gate piped scripts
curl https://example.com/install.sh | portcullis | bash

# Short alias
curl https://example.com/install.sh | pc | bash

# Also works with redirects
portcullis < install.sh | bash
```

### Trust Management

```bash
# Add trusted identities
portcullis trust add alice@example.com
portcullis trust add @chainguard.dev    # trust all emails from a domain

# List and remove
portcullis trust list
portcullis trust remove bob@example.com
```

### Attestations

```bash
# Manually attest to a script hash
portcullis attest --approve sha256:abc123...
portcullis attest --deny sha256:abc123... --reason "exfiltrates env vars"

# Query existing attestations
portcullis query sha256:abc123...
```

## How It Works

When you pipe a script through portcullis:

1. **Buffer** — reads all of stdin
2. **Validate** — checks for binary content, verifies it looks like shell, runs `bash -n` syntax check
3. **Hash** — computes SHA-256 of the content
4. **Cache check** — looks up the hash in local JSON cache (24h TTL)
5. **Rekor query** — searches the Sigstore transparency log for attestations
6. **Decision** — evaluates attestations against your trust list:
   - **Trusted deny** → block immediately
   - **Trusted approve** → pass through to stdout
   - **No trusted signals** → interactive review
7. **Interactive review** — opens the script in your `$EDITOR`, shows attestation context, and prompts:
   - `[a]` Approve + attest (sign and publish to Rekor)
   - `[d]` Deny + attest (sign and publish to Rekor)
   - `[r]` Run anyway (cache locally, no attestation)
   - `[b]` Block anyway (cache locally, no attestation)

All user-facing output goes to stderr. Only the script content (on approve) goes to stdout, preserving pipe semantics.

## Configuration

Config is stored at `$XDG_CONFIG_HOME/portcullis/config.toml` (default `~/.config/portcullis/config.toml`):

```toml
[trust]
identities = [
    "alice@example.com",
]
domains = [
    "@chainguard.dev",
]

[policy]
on_negative = "block"    # block | warn
on_positive = "pass"     # pass | review
on_unknown  = "review"   # review | warn | block
cache_ttl   = "24h"
```

## Security Model

### Protects against
- **Compromised install scripts** — hash changes trigger re-review
- **Blind execution** — forces review of unknown scripts
- **Silent supply chain changes** — new content = new hash = no cached approval

### Does NOT protect against
- Compromised Sigstore identities
- Local cache tampering (mitigated: cache is convenience, Rekor is trust boundary)
- Sophisticated obfuscation (`bash -n` catches syntax, not semantics)
- Runtime payload downloads (gates initial script only)

### Security properties
- All attestations are publicly auditable in Rekor's append-only log
- Signatures tied to verifiable OIDC identities
- Local cache: `0600` permissions, content-hash keyed, 24h TTL
- Never silently passes content when trust infrastructure is unreachable

## Building

```bash
go build -o portcullis .
ln -s portcullis pc  # optional: create short alias
```

## Status

This is an experimental implementation. Sigstore signing (via sigstore-go) and Rekor submission are integrated but not yet battle-tested — the core pipeline (validation, caching, trust management, decision engine, interactive review) is fully functional.
