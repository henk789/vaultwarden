# Reviewed dependency advisory exceptions

This is a reachability assessment of the locked dependency graph, **not a claim
that every dependency is patched**. `deny.toml` names each exception separately
with its reason. All other advisories fail the dependency check. Re-review these
exceptions whenever authentication, TLS features, or the lockfile changes;
remove them when an upstream-compatible patched dependency becomes available.

## RSA: RUSTSEC-2023-0071

`jsonwebtoken 11.1.0` now uses its `aws_lc_rs` backend instead of `rust_crypto`.
Vaultwarden's private JWT signing therefore no longer uses the affected Rust
`rsa` implementation. This is a backend change, not a claim of removing RSA
from the dependency graph.

`rsa 0.9.10` remains through `openidconnect 4.0.1`. The reachable application
path is OIDC signature verification with **public** keys. In the pinned
`openidconnect` source, `src/core/crypto.rs::verify_rsa_signature` constructs
`rsa::RsaPublicKey`; `src/core/jwk/mod.rs` invokes that verifier for IdP tokens.
Vaultwarden constructs its OIDC client using a client secret, not an RSA private
signing/decryption key (`src/sso_client.rs`). The advisory describes recovery of
private keys through private RSA operations, which this remaining path does not
perform. There is no patched `rsa` release identified by this advisory.

**Re-review trigger:** enabling a different JWT backend, OIDC private-key client
authentication, RSA decryption, or any new private operation in `rsa`.

## Rocket TLS: RUSTSEC-2026-0098, 0099, and 0104

The affected `rustls-webpki 0.101.7` is reached through
`rocket 0.5.1 -> rocket_http 0.5.1 -> rustls 0.21.12` (and its `tokio-rustls`
listener). The patched webpki versions are in a newer, incompatible dependency
line; updating only the lockfile cannot substitute that API.

Vaultwarden enables Rocket's `tls` feature, **not `mtls`**, including under the
repository's `--all-features`. In Rocket's pinned `src/config/tls.rs`, the
non-mTLS build supplies `ca_certs: None` and `mandatory_mtls: false`.
`rocket_http/src/tls/listener.rs` consequently selects `NoClientAuth`. This
server does not authenticate peer certificate chains through the affected name
constraint verifier. The application and listener do not configure CRLs or call
the affected `BorrowedCertRevocationList::from_der`/
`OwnedCertRevocationList::from_der` parsers.

Outbound HTTPS uses reqwest's separate, current Rustls dependency chain and
`rustls-webpki 0.103.15`, above all three advisories' patched thresholds. This
assessment does not rely on an operator having disabled Rocket TLS or installed
a reverse proxy, and must not be extrapolated to a custom mTLS build.

**Re-review trigger:** Rocket upgrades, enabling mTLS/client-certificate
verification, CRL parsing, or changes to outbound TLS dependencies.

## PEM maintenance: RUSTSEC-2025-0134

`rustls-pemfile 1.0.4` is an unmaintained transitive Rocket TLS dependency.
Rocket uses it to load local administrator-configured certificate/key files at
startup, not request bodies supplied by remote clients. This is a documented
maintenance exception, not a patched dependency or a dismissal of maintenance
risk. Retain it only while the upstream Rocket dependency requires this API;
remove the exception when Rocket migrates to maintained PEM parsing.

## Reproduce and check assumptions

```sh
cargo tree --locked -i rsa
cargo tree --locked -i rustls-webpki@0.101.7
cargo tree --locked -i rustls-webpki@0.103.15
cargo tree --locked --all-features -e features -i rocket_http
cargo deny --locked --all-features check advisories
```

The advisory check reports these specific accepted exceptions; it is not an
unfiltered clean scan. No wildcard advisory suppression or warning/lint downgrade
is used. The Build workflow runs the same advisory check on relevant changes.
