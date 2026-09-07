# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Umask interference in the directory-permissions test
- GitHub Actions bumped to v7
- Codebase audit: removed obvious/noisy comments, aligned documentation with actual behavior (protected envs, test counts, lint commands), replaced raw `MonkeyPatch()` usage with the pytest fixture

## [1.0.0] - 2026-06-11

### Added

- Secure Conda environment management via three interfaces: Rich TUI, interactive CLI, and argparse CLI
- Four security profiles (Low, Medium, High, Paranoid) with progressive strictness for env names, package names, and filenames
- Cryptographic audit trail with SHA-256 hash chain integrity
- Secure backups with SHA-256 checksum sidecars and path-traversal-safe restore
- Encrypted credential and data stores (Fernet + PBKDF2, 600k iterations)
- Session management with `secrets`-based tokens, TTL, and max-sessions enforcement
- Built-in vulnerability database (20 packages, CVE-aware) and plugin system (`SecurityScanner`, `HealthCheck`)
- CI pipeline: test matrix (Python 3.8–3.12), flake8 critical checks, Bandit and Safety scanning, Codecov coverage
