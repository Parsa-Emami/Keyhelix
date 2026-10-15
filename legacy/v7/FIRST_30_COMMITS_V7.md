# KeyHelix — First 30 Commit Plan v7

These are atomic intent boundaries, not mandatory commit-message text. Do not combine unrelated items merely to hit a number.

1. chore: initialize toolchain manifests and lockfiles
2. ci: make repository validation executable
3. chore: add local development environment/health checks
4. test: add clean-bootstrap smoke test
5. docs: freeze Phase 0 invariants and ADR index
6. phase0: bootstrap authn and device/session model
7. phase0: passkey/WebAuthn flow
8. phase0: step-up policy and freshness window
9. phase0: session binding and revocation
10. test(phase0): add WebAuthn ceremony tests
11. docs(phase0): record exit evidence and ADR updates
12. phase1: vault/member/role domain
13. phase1: deny-by-default authorization
14. phase1: object-level access checks
15. phase1: explicit ownership/recovery roles
16. test(phase1): add authorization matrix tests
17. docs(phase1): record exit evidence and ADR updates
18. phase2: define versioned envelope format
19. phase2: generate random DEK per secret/version
20. phase2: xChaCha20-Poly1305 AEAD with bound metadata
21. phase2: openBao KEK wrapping provider interface
22. test(phase2): add known-answer/round-trip tests
23. docs(phase2): record exit evidence and ADR updates
24. phase3: append-only secret versions
25. phase3: reveal audit context
26. phase3: optimistic concurrency on updates
27. phase3: soft-delete/retention semantics without crypto erasure claims unless implemented
28. test(phase3): add version immutability tests
29. docs(phase3): record exit evidence and ADR updates
30. test: close Phase 0/1 regression or failure-proof gap before scope expansion
