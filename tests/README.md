# Passkey regression tests

`passkey_unlock.rs` launches the real Vaultwarden binary on loopback with a
temporary database, synthetic accounts, signed WebAuthn assertions and encrypted
key fixtures. No identity provider or authenticator hardware is contacted. The
tests do not establish hardware PRF support or stock-client decryption.

Run the portable HTTP cases with SQLite:

```sh
cargo test --locked --features sqlite --test passkey_unlock
```

The PostgreSQL tests require a disposable local PostgreSQL instance. They create
and drop their own `vw_passkey_*` databases. The fixture deliberately accepts
only loopback, the `postgres` maintenance database, and the synthetic credentials
shown below. The test role needs permission to create databases; never use a
production instance or credentials.

```sh
VW_PASSKEY_TEST_DATABASE_URL='postgresql://passkey_test:synthetic-passkey-test@127.0.0.1:15432/postgres' \
  cargo test --locked --features sqlite,postgresql --test passkey_unlock \
  -- --include-ignored --test-threads=1
```

The PostgreSQL-only concurrency and interruption cases are marked `ignore`
because they need that instance. A default test run does not cover them. The
`Passkey PostgreSQL lifecycle and concurrency` job in the existing Build workflow
runs them explicitly against a disposable PostgreSQL service on every relevant
PR or push, including changes under `tests/`.

The lifecycle tests cover atomic passkey deletion/session revocation, rollback
on injected database failures, stale deletion requests racing key rotation,
password changes and account disabling, preservation of unrelated profile and
push metadata, and refresh-token revocation races. Concurrency tests wait for
actual PostgreSQL lock contention instead of relying on arbitrary delays.

Follow the upstream toolchain, database feature matrix and warnings-as-errors
policy in `.github/workflows/build.yml`. In addition to the database tests, run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --profile ci --all-targets \
  --features sqlite,mysql,postgresql,enable_mimalloc,s3 -- -D warnings
```

Native database client libraries are required to build the corresponding
features. The standard CI matrix also tests the MSRV declared in `Cargo.toml`.
Do not weaken lint settings or mark a failing regression ignored to make a
check pass.

Before enabling passkeys for real vaults, separately test compatible clients and
authenticators: enrollment, fresh sign-in, PRF decryption of existing personal
and shared items, master-password fallback, multiple passkeys, removal, and
password/KDF/account-key changes. For SSO-only installations, verify SSO is still
required. Keep backups and a working fallback throughout these checks.
