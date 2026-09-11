# Audit status

This repository has not completed an independent third-party cryptographic
audit. Do not describe it as "audited."

What is in place for reviewers:

- Small TypeScript surface on `@noble/*` (themselves independently audited)
- Protocol spec in SPEC.md
- Known-answer vectors in `vectors/v1.json`
- A second implementation in `verify/verify.py` that must match those vectors
- Unit tests for wrap/unwrap, downgrade rejection, identity signatures, and
  legacy envelope decrypt
