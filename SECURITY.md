# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| < 2.0   | No        |

## Reporting a Vulnerability

Please report security vulnerabilities **privately** through GitHub Security Advisories:

<https://github.com/Morphilab/nebulaforge/security/advisories/new>

Do **not** open a public issue, discussion, or pull request for a security vulnerability.

Include as much detail as you can: affected version or commit, reproduction steps, impact, and any
suggested fix. We will acknowledge the report and coordinate disclosure after the issue has been
investigated and a fix is available.

## Scope

This policy covers the NebulaForge package and its command-line interfaces. It does not cover
third-party tools that NebulaForge invokes, such as Conda, Mamba, or packages installed into a user
environment.

## Security Model Notes

- The audit log uses an unkeyed SHA-256 hash chain. It detects accidental or casual modification,
  but it is not a substitute for an external, append-only log or a keyed signature.
- Backups and their `.sha256` sidecars live in the same directory. The checksum detects corruption
  and accidental modification; it is not a defense against an attacker who can rewrite both files.
- Production mode is a read-only policy enforced by NebulaForge. It does not sandbox Conda itself.
