# KeyHelix: completion endpoint

Current: C01–C35 verified (`core_ready: true`); C36–C40 OSS publication and installed-host proof pending.

## C30: locally usable (Verified)

All C01–C30 acceptance and negative cases have source-bound evidence. A supported host completes `git clone`, `npm run setup`, `npm start`, the entire `REFERENCE_WORKFLOW.md` task, restart and restore using the actual engine, durable storage port, OpenBao, and Keycloak providers.

## C31: complete reproducible artifact (Verified)

`npm run package` produces a complete local artifact containing the actual Go engine, web UI, offline contracts/rules references, provider templates, source archive/build recipes, CycloneDX SBOM, upstream notices and license texts, SHA-256 checksums and provenance. Unknown licenses and secret-bearing payloads fail closed; publication is atomic and recovers the prior or new complete state after a killed writer or exhausted quota. The artifact records whether the source tree was dirty. Publication, signatures and installed-host workflow remain C39/C40 work.

## C39/C40: complete OSS v1

C39 verifies actual C01–C38 proof, full source/engine packaging, dependency/fixture licenses, security/recovery, UX, upgrade and independent onboarding. `npm run release:check` fails on missing or unverified work. C40 then publishes through the maintainer-authorized source/tag/artifact workflow, installs the actual published version and repeats the complete reference task. Only then may complete v1 be verified.

Planning files, forty commits, green shell CI or a web-only package are not completion evidence. Customer pilots, marketing domains, billing and app stores are not local OSS requirements. Untrusted public execution, multi-tenant SaaS and unbounded resources are outside this v1 profile. Protected-file restrictions remain in force.
