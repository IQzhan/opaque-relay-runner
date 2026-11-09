# `opaque-relay-runner` — Zero-Leakage Stateless Opaque Execution Relay

`opaque-relay-runner` is a stateless, zero-plaintext-log public execution relay governed by [`RULES.md`](RULES.md).

## 1. Architectural Responsibilities
- **Zero Private Metadata Storage**: This repository stores zero business logic, zero target repository identifiers, zero cloud storage identifiers, and zero credentials in its source tree or workflow definitions.
- **Authenticated Ephemeral Envelope Protocol**: Execution requests arrive exclusively as `HMAC-SHA256-CTR + HMAC-SHA256` authenticated ciphertext packets (`OPAQUE_PACKET`) paired with masked ephemeral key shares (`OPAQUE_SHARE` / `OPAQUE_SECRET`).
- **Complete Console Log Silence**: All standard output and standard error streams during execution are captured exclusively in memory, encrypted via authenticated stream encryption, and transmitted as ciphertext telemetry (`opaque_relay_telemetry.enc.json`). The GitHub Actions console displays only a constant completion marker (`[OPAQUE-RELAY] status=completed`).
- **Healthy Low-Frequency Anti-Abuse Cadence**: Strictly event-driven (`0` cron schedules), enforcing a 45-second coalescing debounce window, content-hash idempotency, and a sliding-window hourly execution cap (`<= 30` runs/hour).
