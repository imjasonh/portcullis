# Portcullis — Engineering Plan

**Your machine is a castle. `curl | bash` is an open gate. Portcullis drops the gate and inspects what’s trying to enter.**

Portcullis is a CLI tool that interposes in shell script execution pipelines to verify trust before allowing execution. It uses Sigstore for identity and Rekor as a public transparency log for trust attestations.

-----

## 1. Usage Model

```bash
# Primary use case: gate piped scripts
curl https://example.com/install.sh | pc | bash

# Also works with redirects
pc < install.sh | bash

# Trust management
portcullis trust add alice@example.com
portcullis trust add @chainguard.dev
portcullis trust list
portcullis trust remove bob@example.com

# Manual attestation (outside pipe flow)
portcullis attest --approve sha256:abc123...
portcullis attest --deny sha256:abc123... --reason "exfiltrates env vars to remote server"

# Query attestations for a hash
portcullis query sha256:abc123...

# Authenticate with Sigstore
portcullis auth
```

`pc` is a symlink to `portcullis` that implies pipe mode. The full name is used for subcommands.

-----

## 2. Core Pipe Flow

```
stdin (script bytes)
│
├─ 1. Buffer entire stdin
│
├─ 2. Shell validation
│     ├─ Check for null bytes → block (binary, not a script)
│     ├─ Heuristic: first lines look like shell? (shebang, keywords)
│     ├─ bash -n syntax check → block on failure
│     └─ On block: print first 10 lines to stderr, exit 1
│
├─ 3. Compute SHA-256 hash
│
├─ 4. Check local cache (SQLite)
│     ├─ Cache hit within TTL (24h) with "approve" → pass to stdout, done
│     └─ Cache hit within TTL with "deny" → block, done
│
├─ 5. Query Rekor for attestations on this hash
│     ├─ Collect all attestations (positive and negative)
│     ├─ Partition into: trusted (in trust graph), unknown (not in trust graph)
│     └─ If Rekor unreachable: fall back to expired cache, else treat as unknown
│
├─ 6. Decision logic
│     │
│     ├─ NEGATIVE signal from trusted identity
│     │   → Block. Print who flagged it, when, and why. Exit 1.
│     │
│     ├─ POSITIVE signal from trusted identity (no negatives from trusted)
│     │   → Pass script to stdout. Print attestor info to stderr.
│     │
│     └─ NO signal from trusted identities
│         → Enter interactive review (see below)
│
└─ 7. Interactive review (via /dev/tty)
      ├─ Display: script content in $EDITOR or pager with syntax highlighting
      ├─ Display: any unknown attestations as context
      │   "3 unknown identities have approved this:
      │    - alice@redhat.com (2026-03-15)
      │    - bob@chainguard.dev (2026-03-20)"
      │   "1 unknown identity has flagged this:
      │    - mallory@evil.com (2026-03-28): 'sends env to remote host'"
      ├─ Prompt options:
      │   [a] Approve + attest — sign positive attestation, publish to Rekor, pass to stdout
      │   [d] Deny + attest   — sign negative attestation, publish to Rekor, block
      │   [r] Run anyway       — pass to stdout, no attestation, cache locally
      │   [b] Block anyway     — block, no attestation, cache locally
      └─ Cache the decision locally with 24h TTL

All user-facing output → stderr
Interactive prompts → /dev/tty
Script content (on approve/run) → stdout
```

-----

## 3. Architecture

```
portcullis CLI (Go binary)
│
├── cmd/                        # CLI entrypoints
│   ├── root.go                 # pipe mode (default when no subcommand)
│   ├── trust.go                # trust add/remove/list
│   ├── attest.go               # manual attest --approve/--deny
│   ├── query.go                # query attestations by hash
│   └── auth.go                 # sigstore OIDC login
│
├── internal/
│   ├── gate/                   # Core gate logic
│   │   ├── gate.go             # Orchestrates the full pipe flow
│   │   ├── validate.go         # Shell validation (null bytes, heuristics, bash -n)
│   │   └── decision.go         # Decision engine (trusted/untrusted/unknown logic)
│   │
│   ├── rekor/                  # Rekor client
│   │   ├── client.go           # Query and submit attestations
│   │   └── attestation.go      # Custom attestation type for portcullis
│   │
│   ├── sigstore/               # Sigstore integration
│   │   ├── signer.go           # Sign attestations via OIDC identity
│   │   └── verify.go           # Verify attestation signatures
│   │
│   ├── trust/                  # Trust graph
│   │   ├── store.go            # Read/write trusted identities from config
│   │   └── match.go            # Match attestation identity against trust list
│   │                           # (exact email or @domain)
│   │
│   ├── cache/                  # Local decision cache
│   │   ├── db.go               # SQLite operations
│   │   └── schema.go           # Table definitions, migrations
│   │
│   └── review/                 # Interactive review UI
│       ├── editor.go           # Open script in $EDITOR via /dev/tty
│       ├── pager.go            # Fallback pager with syntax highlighting
│       └── prompt.go           # [a]pprove/[d]eny/[r]un/[b]lock prompt via /dev/tty
│
├── config.toml                 # User configuration
└── go.mod
```

-----

## 4. Data Model

### 4.1 Portcullis Attestation (stored in Rekor)

```json
{
  "_type": "https://portcullis.dev/attestation/v1",
  "subject": {
    "sha256": "abc123..."
  },
  "verdict": "approve" | "deny",
  "reason": "optional human-readable reason",
  "identity": "jane@example.com",
  "timestamp": "2026-03-31T12:00:00Z"
}
```

This is signed with the user’s Sigstore keyless identity and submitted to Rekor as a custom attestation type. Rekor provides the transparency log entry, inclusion proof, and signed timestamp.

### 4.2 Local Cache (SQLite)

```sql
CREATE TABLE decisions (
    script_hash TEXT NOT NULL,
    verdict     TEXT NOT NULL,       -- 'approve', 'deny'
    source      TEXT NOT NULL,       -- 'local' (run/block anyway) or 'attested'
    identity    TEXT,                -- signer email if attested
    reason      TEXT,
    created_at  INTEGER NOT NULL,    -- unix timestamp
    expires_at  INTEGER NOT NULL,    -- created_at + 86400 (24h)
    PRIMARY KEY (script_hash)
);
```

File location: `$XDG_CONFIG_HOME/portcullis/cache.db` (default `~/.config/portcullis/cache.db`)
Permissions: `0600` (user read/write only)

### 4.3 Config File

Location: `$XDG_CONFIG_HOME/portcullis/config.toml`

```toml
[trust]
identities = [
    "alice@example.com",
    "bob@chainguard.dev",
]
domains = [
    "@redhat.com",
    "@google.com",
]

[policy]
on_negative = "block"       # block | warn
on_positive = "pass"        # pass | review
on_unknown  = "review"      # review | warn | block
cache_ttl   = "24h"
```

-----

## 5. Implementation Plan

### Phase 1: Core pipe and validation (week 1)

**Goal:** `cat script.sh | portcullis` validates shell, hashes, and passes through or blocks.

- [ ] Project scaffolding: Go module, CLI with cobra, config loading
- [ ] Pipe mode: read all of stdin into buffer
- [ ] Shell validation:
  - Null byte check (reject binary input)
  - Heuristic check (shebang, common shell tokens in first 20 lines)
  - `bash -n` syntax check via `os/exec`
  - On failure: print diagnostic to stderr, exit 1
- [ ] SHA-256 hashing of validated content
- [ ] Pass-through to stdout on success (no Rekor yet, just validate + hash + pass)
- [ ] Tests: valid scripts pass, binaries blocked, HTML error pages blocked, malformed shell blocked

### Phase 2: Sigstore + Rekor integration (week 2)

**Goal:** Query and publish attestations.

- [ ] Sigstore OIDC auth flow (`portcullis auth`)
  - Use sigstore-go SDK for keyless signing
  - Store OIDC token refresh in config dir
- [ ] Define custom Rekor attestation type
- [ ] Rekor query: given a SHA-256 hash, fetch all portcullis attestations
  - Parse response into list of (identity, verdict, reason, timestamp)
- [ ] Rekor submit: publish a signed attestation (approve or deny)
- [ ] `portcullis attest --approve <hash>` and `--deny <hash> --reason "..."`
- [ ] `portcullis query <hash>` — display attestations found
- [ ] Tests: mock Rekor responses, verify attestation signing/verification round-trip

### Phase 3: Trust graph + decision engine (week 3)

**Goal:** Trust management and automated decisions in pipe mode.

- [ ] `portcullis trust add/remove/list` — manage config.toml identity list
- [ ] Trust matching: exact email match and @domain suffix match
- [ ] Decision engine:
  - Partition Rekor results into trusted vs unknown
  - Apply policy rules (negative from trusted → block, positive from trusted → pass, etc.)
  - Print decision context to stderr (who attested, when, verdict)
- [ ] Integrate into pipe flow: hash → query Rekor → decision → pass or block
- [ ] Handle Rekor unreachable: log warning to stderr, proceed to review
- [ ] Tests: various attestation scenarios, domain matching, policy modes

### Phase 4: Local cache (week 3-4)

**Goal:** Don’t re-query Rekor for scripts you’ve already decided on.

- [ ] SQLite cache: init DB on first run, create schema
- [ ] Cache check before Rekor query
- [ ] Cache write after decision (both attested and local-only decisions)
- [ ] TTL expiry: ignore entries older than configured TTL
- [ ] File permissions: create with `0600`
- [ ] Tests: cache hit/miss/expiry, corrupted DB recovery

### Phase 5: Interactive review (week 4)

**Goal:** Editor-based review for unknown scripts.

- [ ] Open `/dev/tty` for interactive I/O (separate from stdin/stdout pipe)
- [ ] Editor flow: write script to temp file, open in `$EDITOR`, wait for exit
- [ ] Pager fallback: if no `$EDITOR`, use `less` with syntax highlighting
- [ ] Display unknown attestation context before prompt
- [ ] Four-option prompt: `[a]pprove + attest` / `[d]eny + attest` / `[r]un anyway` / `[b]lock anyway`
- [ ] On approve+attest: sign and publish to Rekor, cache, pass to stdout
- [ ] On deny+attest: sign and publish to Rekor, cache, exit 1
- [ ] On run/block anyway: cache locally only, pass or block
- [ ] Handle non-interactive context (no TTY): fall back to policy default (block by default)
- [ ] Tests: mock /dev/tty interactions

### Phase 6: Polish + distribution (week 5)

- [ ] `pc` symlink / alias detection for pipe mode
- [ ] `--version`, `--help`, man page
- [ ] Error messages: clear, actionable, always to stderr
- [ ] Graceful handling of SIGPIPE (if bash exits early)
- [ ] CI/CD: GitHub Actions for build, test, release
- [ ] Goreleaser config for cross-platform binaries
- [ ] README with threat model, usage examples, trust model explanation
- [ ] Document cache security properties and limitations
- [ ] Homebrew formula / install script (yes, the irony)

-----

## 6. Key Dependencies (Go)

|Dependency            |Purpose                        |
|----------------------|-------------------------------|
|`sigstore/sigstore-go`|Keyless signing, OIDC auth     |
|`sigstore/rekor`      |Transparency log client        |
|`spf13/cobra`         |CLI framework                  |
|`mattn/go-sqlite3`    |Local cache                    |
|`mattn/go-isatty`     |Detect TTY for interactive mode|

-----

## 7. Threat Model

### What portcullis protects against

- **Compromised install scripts** — a script you previously trusted changes to include malicious payloads; someone in your trust graph catches it and publishes a negative attestation.
- **Blind execution** — forces first-time reviewers to actually look at what they’re running.
- **Silent supply chain changes** — any change to a script produces a new hash, which has no cached approval, triggering re-review.

### What portcullis does NOT protect against

- **Compromised Sigstore identity** — if an attacker controls a trusted identity’s OIDC provider, they can publish false attestations. Mitigation: Sigstore’s transparency logs make this detectable after the fact.
- **Local cache tampering** — an attacker with your user privileges can modify the SQLite cache to whitelist a malicious hash. Mitigation: if they have your user privileges, you’ve already lost. Cache is a convenience layer; Rekor is the trust boundary.
- **Sophisticated obfuscation** — `bash -n` catches syntax errors but not semantically malicious scripts. Human review is the real gate.
- **Collusion** — multiple trusted identities coordinating to approve malicious content. Mitigation: none at the tool level; this is a social problem.
- **Time-of-check/time-of-use** — the script could theoretically download additional payloads at runtime. Portcullis gates the initial script, not its runtime behavior.

### Security properties

- All attestations are publicly auditable in Rekor’s append-only log.
- Attestation signatures are tied to verifiable OIDC identities (email addresses).
- Local cache is `0600` permissions, keyed by content hash, and expires after 24h.
- Portcullis never silently passes through content when the trust infrastructure is unreachable (defaults to interactive review or block).

-----

## 8. Open Questions

1. **Attestation revocation.** Can a user revoke a previous approval? Rekor is append-only, so revocation would be a new “deny” attestation by the same identity. The decision engine would need to handle “alice approved this on March 1 but denied it on March 15” — latest attestation wins? Or deny always wins?
- **Recommendation:** Deny wins over approve from the same identity. Latest wins for same-verdict updates.
1. **Rate limiting on Rekor queries.** If portcullis becomes popular, every `curl | pc | bash` invocation hits Rekor. Is this sustainable?
- **Recommendation:** Local cache (24h TTL) handles the common case. For CI/CD, consider a `--offline` flag that only uses the local cache.
1. **Attestation spam.** Can an attacker flood Rekor with fake approvals to make a malicious script look well-reviewed?
- **Recommendation:** Unknown attestations are displayed as context but never auto-trusted. Only trusted-graph attestations drive decisions. Spam is noise, not a bypass.
1. **Team/org onboarding.** How does a team share a trust list?
- **Recommendation:** Config file is just TOML. Teams can check it into a repo or distribute via config management. Future work: `portcullis trust import <url>`.
1. **Non-bash scripts.** Python/Ruby/Perl install scripts piped through `tg`?
- **Recommendation:** v1 is bash-only (`bash -n` validation). Future versions could detect shebang and validate accordingly. The trust/attestation layer is language-agnostic.
