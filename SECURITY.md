# Security Policy

## Reporting a vulnerability

Report security issues to: **<security@cloudflare.com>**

Include in your report:

- A description of the vulnerability and its impact.
- Steps to reproduce or a proof-of-concept.
- The version(s) affected.
- Any suggested mitigation or fix, if known.

## Scope

The following are in scope for this policy:

- Cryptographic vulnerabilities in the ARC protocol implementation
  (timing side-channels, forgery, malleability, soundness failures).
- Panics or memory-safety issues reachable through the public API.
- Vulnerabilities in the serialization logic.

The following are **out of scope**:

- Vulnerabilities in dependency crates, report these to their respective maintainers. 
- Theoretical weaknesses in the ARC protocol itself. File these against the
  [ARC draft](https://github.com/ietf-wg-privacypass/draft-arc/issues).
