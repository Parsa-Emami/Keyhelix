# KeyHelix — Dependency Policy v7

## Reference dependencies
- openbao
- libsodium/php sodium
- webauthn library behind adapter
- postgresql
- valkey
- opentelemetry

All dependencies require exact source/license/security tracking. Vendor-specific libraries stay in Infrastructure adapters. Scanner/rule/model outputs are normalized before entering Domain. Third-party Actions/images are SHA/digest pinned in release paths.
