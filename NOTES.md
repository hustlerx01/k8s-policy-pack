# NOTES
- 2026-10-11: 48/48 kyverno test, 9/9 rego unit, 6/6 pytest parity. kind not available (no docker).
- Gotcha: the `kyverno test` table shows "Pass" when the *expectation* is met, not when the resource passed. Verified with `kyverno apply` (7 real fails) and a mutation test.
- Finding: the registry-port bypass of `*:*` in the latest-tag pattern (see README).
- Interview angles: admission vs CI shift-left, why to test policies like code, autogen, Enforce vs Audit rollout, CEL migration.
- Next: CEL ValidatingPolicy versions, a PolicyException demo, run kind e2e in CI.
