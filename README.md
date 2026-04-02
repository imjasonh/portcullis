# Portcullis


<p align=center>
<img align=center width="20%" src="https://github.com/user-attachments/assets/92891d6a-b11d-4d88-aaa5-982716e3e631">
</p>

<p align=center>
<i>Portcullis (n.): a thing that keeps the bad stuff out of the place.</i>
</p>

**Your machine is a castle. `curl | bash` is an open gate. Portcullis drops the gate and inspects what's trying to enter.**

Portcullis is a CLI tool that interposes in shell script execution pipelines to verify trust before allowing execution. It uses Sigstore for identity and Rekor as a public transparency log for trust attestations.

A lot of words have been written about the relative insecurity of doing `curl | bash`, and I won't write more here ([here's some good ones!](https://sandstorm.io/news/2015-09-24-is-curl-bash-insecure-pgp-verified-install)). Suffice to say, the people seem to like the convenience of it. I wondered if there was a way to get the usability benefit of it, without the security issues about blind code execution. Portcullis is an experiment to try to get the best of both worlds.

## Install

```bash
go install github.com/imjasonh/portcullis@latest
```

## Usage

```bash
# Primary use case: gate piped scripts
curl https://example.com/install.sh | portcullis | bash

# Also works with redirects
portcullis < install.sh | bash
```

`portcullis` buffers stdin and checks the [Rekor](https://docs.sigstore.dev/logging/overview/) transparency log for determinations about that content by its SHA-256 digest. If someone you trust has publicly approved the contents, it will be passed through to `bash`. If someone you trust has reported it as malicious, it will be blocked.

If none of your trusted users have approved or denied yet, you will be shown the contents and asked to approve or deny, and your decision will be written to Rekor for future `portcullis` users.

### Trust Management

```bash
# Add trusted identities
portcullis trust add alice@example.com
portcullis trust add @example.com    # trust all emails from a domain

# List and remove
portcullis trust list
portcullis trust remove bob@example.com
```

### Cache Management

```bash
# Clear the local decision cache
portcullis clean
```

### Attestations (without `curl|bash`)

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
4. **Cache check** — looks up the hash in local JSON cache (24h TTL, `~/.config/portcullis/cache.json`)
5. **Rekor query** — searches the Sigstore transparency log for attestations for the hash
6. **Decision** — evaluates attestations against your trust list:
   - **Trusted deny** → block immediately
   - **Trusted approve** → pass through to stdout
   - **No trusted signals** → interactive review
7. **Interactive review** — opens the script in your configured `$EDITOR`, shows attestation context, and prompts:
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
- **Blind execution** — forces review of unknown scripts; what is buffered is exactly what gets passed to `bash`
- **Silent supply chain changes** — new content = new hash = no cached approval

### Does NOT protect against
- Compromised Sigstore identities (e.g., someone hacking `alice@example.com`'s account to approve a malicious script)
- Sophisticated obfuscation; you are responsible for reviewing and understanding the script
- Runtime payload downloads; if the script downloads something else, `portcullis` won't block that

### Security properties
- All attestations are publicly auditable in Rekor's append-only log
- Signatures tied to verifiable OIDC identities
- Local cache: `0600` permissions, content-hash keyed, 24h TTL
- Never silently passes content when trust infrastructure is unreachable

## Status

This is an experimental project. Things work, but should be expected to change in breaking ways. Always install responsibly.
