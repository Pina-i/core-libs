# CLAUDE.md — core-libs

## Project Context

This is the **shared internal Rust library** of the Pina-i platform, a self-hostable, federated, open-source Discord alternative built under the GitHub organization `Pina-i`.

This repo is not a deployable service. It is a **Cargo workspace of reusable crates** consumed by `identity-provider` and `chat-server` as path or git dependencies.

## Why This Exists

Both `identity-provider` and `chat-server` share overlapping logic:

- JWT validation (both services validate JWTs)
- HTTP Signatures (used by identity-provider; must be verifiable by anyone)
- ActivityPub types (shared data model for federation)
- Common API types and error formats (DTOs used across service boundaries)

Centralizing this logic here ensures consistent behavior, a single place for security review, and no divergence between implementations.

## Crate Structure

```
core-libs/
├── Cargo.toml                  # workspace root
├── crates/
│   ├── jwt-utils/              # JWT issuance, validation, JWKS client + cache
│   ├── http-signatures/        # HTTP Signature signing and verification (Cavage draft)
│   ├── activitypub/            # ActivityPub types: Actor, Note, Follow, Accept, etc.
│   └── common-types/           # Shared error types, pagination, API response wrappers
```

## Crate Responsibilities

### `jwt-utils`

- JWT issuance with Ed25519 and RS256
- JWT validation: signature, `exp`, `iat`, `iss`, `aud`, `nonce`
- JWKS client: fetch remote JWKS, cache with TTL, refetch on key rotation
- PKCE helpers: `code_verifier` generation, `code_challenge` computation (S256)
- Key ID (`kid`) selection from JWKS by algorithm

**Key constraint**: This crate must never take a hard dependency on Axum or any specific web framework. It must be framework-agnostic.

### `http-signatures`

- Sign outgoing HTTP requests with an Ed25519 private key (ActivityPub delivery)
- Verify incoming HTTP request signatures using a known public key
- Compatible with the Cavage HTTP Signatures draft (used by Mastodon and ActivityPub ecosystem)
- Header coverage: `(request-target)`, `host`, `date`, `digest`
- Digest computation (SHA-256) for POST body integrity

**Key constraint**: This crate must not depend on any specific HTTP client or server library. Accept and return raw header maps.

### `activitypub`

- Strongly typed Rust structs for core ActivityPub vocabulary:
  - `Actor` (Person, Service)
  - `Follow`, `Accept`, `Reject`, `Undo`
  - `Note` (for DMs)
  - `OrderedCollection`, `OrderedCollectionPage` (inbox/outbox)
- JSON-LD context handling (`@context`)
- Serialization/deserialization via `serde_json`
- WebFinger response types

**Key constraint**: Structs must round-trip correctly with real Mastodon instances for interoperability.

### `common-types`

- Shared API error type with HTTP status codes
- Pagination types (`CursorPage`, `OffsetPage`)
- Standard JSON response envelope
- Domain identifier types: `UserId`, `ServerId`, `ChannelId` (newtype wrappers around UUIDs)

## Consuming These Crates

In `identity-provider/Cargo.toml` or `chat-server/Cargo.toml`:

```toml
# During development (path dependency)
[dependencies]
jwt-utils = { path = "../core-libs/crates/jwt-utils" }
http-signatures = { path = "../core-libs/crates/http-signatures" }
activitypub = { path = "../core-libs/crates/activitypub" }
common-types = { path = "../core-libs/crates/common-types" }

# After publishing or using git dependency
jwt-utils = { git = "https://github.com/pina-i/core-libs", tag = "v0.1.0" }
```

## Related Repositories

| Repo | Consumes |
|------|---------|
| `pina-i/identity-provider` | All four crates |
| `pina-i/chat-server` | `jwt-utils`, `common-types` |

## Design Constraints

- **No framework dependencies** in `jwt-utils` or `http-signatures` — these must be usable in any Rust async runtime
- **No database dependencies** in any crate — data access belongs in the consuming service
- **Minimal `unsafe`** — if needed, document clearly with a safety comment
- **`no_std` compatibility** is not required but avoid gratuitous `std`-only APIs
- Each crate must have its own `README.md` documenting public API and usage examples

## Versioning

- Each crate is versioned independently using semantic versioning
- Breaking changes in any crate require a major version bump
- Crates are not published to crates.io (private to the Pina-i org) — consumed via git dependency with tag pinning

## Testing Strategy

- Each crate has thorough unit tests
- `http-signatures`: test round-trip sign → verify with known vectors from the spec
- `jwt-utils`: test with expired tokens, wrong issuer, key rotation scenarios
- `activitypub`: test JSON round-trip against real Mastodon actor payloads (save fixtures in `tests/fixtures/`)
