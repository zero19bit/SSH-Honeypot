# Security Model

## Non-negotiable invariant

Attacker-controlled input is never passed to a host shell, process launcher,
filesystem API, DNS resolver, or outbound network client. `commands.py`,
`filesystem.py`, and `fake_data.py` operate only on per-session Python state.

The real attack surface is limited to:

- the inbound TCP listener;
- Paramiko and its cryptographic dependencies;
- JSON events written to stdout;
- configuration read from CLI arguments and environment variables.

## Defense in depth

Production mode requires a stable host key and a non-privileged internal port.
The supplied Compose profile adds:

- a numeric non-root user;
- read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges`;
- private PID/IPC namespaces (Docker defaults);
- a dedicated Docker bridge; egress must be blocked by the host/cloud policy;
- CPU, memory, process and file-descriptor limits;
- bounded and rotated Docker logs;
- restart policy and graceful SIGTERM handling.

The application independently enforces global/per-IP connection limits,
token-bucket admission rates, session timeouts, command/history limits, output
limits, and in-memory filesystem quotas.

## Credentials and privacy

Password attempts may be sensitive or regulated data. Three modes exist:

- `plain`: preserve attempted passwords for development research only; rejected in production;
- `sha256` (default): store only an unsalted one-way digest and length;
- `redact`: store only the length.

Existing `.env` files that explicitly select `plain` must be updated before
production startup. Hashes of common passwords may be guessed; use `redact`
when a digest is unnecessary. Raw commands may still contain credentials.
Restrict access to container logs and configure a retention period. Never send
captured credentials to third parties without a lawful basis.

## Deployment boundary

Do not run this process as root or beside valuable workloads. Prefer a separate
VM/VPS dedicated to deception. Keep management SSH on a different private
interface, VPN, or tightly allowlisted port. Compose currently sets
`internal: false`, so block outbound traffic at the host/cloud firewall and
validate the restriction before exposing the listener publicly.

## Log integrity and IOC privacy (3.0.1)

The JSONL writer chains SHA-256 digests in actual output order; the standalone
`tools/analyze_log.py` verifies a single process run. This detects alterations
within a collected file, but a party able to rewrite and recompute all records
can forge a new chain. The truncated end of a file cannot be detected without
an external checkpoint. Keep immutable or remote copies of production logs.
High-cardinality IOC and history state is bounded per session; only short safe
artifact filenames may appear in URL IOCs. Raw command events can still contain
passwords, tokens or command arguments, so protect the original JSONL stream.

## Supply chain

Runtime packages are exact-pinned with hashes in `requirements.lock`. CI should
run `pip-audit`, tests and a fresh container build before each release. Pin the
Docker base-image digest in your own registry after validating an update.

## Reporting

If an input can execute a real process, read/write a host file, or create an
outbound connection, treat it as a critical vulnerability and remove the
deployment from the network until fixed.

## Offline intelligence in version 3

The SSH runtime keeps only bounded per-session indicators and writes events to
the existing JSONL stream. It does not access host log files, open a database,
make outbound requests, or execute downloaded material. `tools/intel_report.py`
is an analyst-run program outside the container and is never imported by the
SSH server. It reads a user-supplied JSONL file and writes a user-supplied local
SQLite database. Passwords are not imported, and raw commands are omitted
unless `--include-commands` is explicitly chosen. Original JSONL logs can
still contain sensitive attempted credentials and commands.
