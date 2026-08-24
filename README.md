# cliptown-test/security-boundary-tests

Tenant isolation, replay protection, signature verification, path traversal, SSRF, redaction, and CI supply-chain boundary tests.

The suite also models ClipTown's Bluetooth/proximity boundary: closed envelopes,
32 KiB and 120-second caps, digest and enrolled-key verification, recipient/session
binding, monotonic sequences, replay rejection, credential-field rejection, and
the rule that radio observations never become Shared Auth/3FA assurance.

This repository is the `security` deep-test suite for `cliptown`. It is intentionally dependency-light and deterministic so failures can be reproduced locally without production credentials or customer data.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

The initial model is executable rather than a placeholder. Product adapters should be added through focused pull requests while preserving the reference-model tests as an oracle.

Tracking: https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
