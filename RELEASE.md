# Release checklist — v3.0.1

This checklist records what was verified while producing this source archive.
Checked items are evidence from this build environment, not claims about the
recipient's Docker host.

- [x] Intelligence rules, cache, scoring, IOC extraction and structured logs implemented.
- [x] Version updated in runtime, package metadata and Compose image.
- [x] New targeted unittest cases and legacy unittest modules passed.
- [x] Existing pure Python command, shell, VFS, load and security invariant functions passed.
- [x] AST security guards detected no host process launch or host file access in runtime.
- [x] Python source compiled and offline package wheel built.
- [x] README.md, SECURITY.md, OPERATIONS.md and CHANGELOG.md updated.
- [ ] Full pytest including real Paramiko client/server integration (dependencies unavailable here).
- [ ] Docker image build and container healthcheck (Docker unavailable here).
- [ ] Dependency vulnerability audit with pip-audit (unavailable here).
- [ ] Host or cloud egress firewall tested on the deployment machine.

**Release gate:** Complete all unchecked items before internet exposure.
The supplied Compose bridge allows egress until blocked externally. The
SHA-256 chain detects edits in collected records but provides no authenticity
against someone who can recompute the whole chain.
