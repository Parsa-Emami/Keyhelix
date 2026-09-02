# KeyHelix

> v7.0 status: **ARCHITECTURE-GO / BOOTSTRAP-GO / SOURCE-NOT-IMPLEMENTED**

This directory is a standalone GitHub repository starting point for KeyHelix. It contains the frozen architecture/specification, valid HTTP/event/configuration contracts, GitHub governance/security controls, and project-specific source bootstrap commands.

## Runtime boundary
- Laravel 13 control plane/API
- PHP sodium/libsodium
- OpenBao 2.6.x for KEK/signing
- PostgreSQL 18.6
- Valkey
- S3-compatible signed audit checkpoint storage
- OpenTelemetry with secret redaction

## First executable proof
Vault → generated DEK → XChaCha20-Poly1305 encryption → step-up reveal → KEK rewrap → tamper rejection → signed audit checkpoint.

## Start
```bash
make validate
# verify the GitHub owner/module namespace first
make bootstrap
```

Read `ROADMAP_V7.md`, `PROJECT_START_CHECKLIST_V7.md`, `ACCEPTANCE_GATES_V7.md`, and `GITHUB_REPOSITORY_SETUP_V7.md` before the first code commit.

## Evidence rule
Architecture readiness is not production readiness. “S-tier”, “secure”, “resilient”, or performance claims require executable test/observability/failure/recovery/benchmark/release evidence.

## v7 portfolio position
Recommended implementation order: **9 / 10**. Secrets management is unforgiving. A portfolio demo is worthwhile only if cryptographic boundaries, recovery, audit and review are disciplined.
