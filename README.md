# NebulaForge

**English** | [Español](README.es.md)

**Forge secure, auditable Conda environments**

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://github.com/Morphilab/nebulaforge/actions/workflows/tests.yml/badge.svg)](https://github.com/Morphilab/nebulaforge/actions)
[![codecov](https://codecov.io/gh/Morphilab/nebulaforge/branch/main/graph/badge.svg)](https://codecov.io/gh/Morphilab/nebulaforge)
[![Version](https://img.shields.io/badge/version-2.0.0-blue)](https://github.com/Morphilab/nebulaforge/releases)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow)](https://github.com/PyCQA/bandit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000)](https://github.com/astral-sh/ruff)
[![Mypy checked](https://img.shields.io/badge/mypy-checked-blue)](http://mypy-lang.org/)
[![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen)](https://github.com/Morphilab/nebulaforge/graphs/commit-activity)

---

## Why NebulaForge?

Managing Conda environments securely and reproducibly is challenging. NebulaForge solves this by providing **layered security controls**, audit trails with SHA-256 chain integrity, verified backups, vulnerability scanning, and a modern Rich-based terminal interface — all in one extensible tool.

Whether you are an individual developer who cares about reproducibility, a data-science team that needs audit trails, or a security-conscious organization that needs strict environment isolation, NebulaForge has a security profile for you.

---

## Key Features

- **Three Interfaces**: Rich-based TUI, interactive step-by-step CLI, and traditional argparse CLI
- **Four Security Profiles**: Low, Medium, High, and Paranoid — each with progressively stricter controls
- **Audit Trail**: SHA-256 hash chain on every audit entry
- **Secure Backups**: Automatic pre-deletion and pre-restore backups, with SHA-256 checksum verification
- **Atomic Restore**: Restores build a temporary environment and swaps it into place with rollback; a failed restore never deletes the live target
- **Vulnerability Scanner**: Built-in detection of 20 known vulnerable packages (CVE-aware)
- **Plugin System**: Extensible architecture with `SecurityScanner` and `HealthCheck` built-ins
- **Encrypted Storage**: Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 (600k iterations) for credentials and secrets
- **Session Management**: Cryptographically secure tokens with TTL and max-sessions enforcement
- **Strict Validation**: Malware keyword blocking, dangerous pattern detection, profile-aware strictness
- **Python 3.12**: Pinned via uv (`uv.lock` + `.python-version`)

---
## ⚠️ AI Disclosure / Divulgación de IA

**English:**  
This project was developed with assistance from artificial intelligence tools. Given the automated nature of some components, users are advised to review and test the code independently before integrating it into their own systems.

**Español:**  
Este proyecto fue desarrollado con asistencia de herramientas de inteligencia artificial. Dada la naturaleza automatizada de algunos componentes, se recomienda que los usuarios revisen y prueben el código independientemente antes de integrarlo en sus propios sistemas.

---

## Quick Start

```bash
# Clone and install (uv, Python 3.12 pinned)
git clone https://github.com/Morphilab/nebulaforge.git
cd nebulaforge
uv sync
uv run nebulaforge --help

# Launch the TUI (recommended for first-time users)
nebulaforge

# Or use the interactive step-by-step CLI
nebulaforge interactive

# Or run a one-shot command
nebulaforge list
nebulaforge create my-project --python 3.11
nebulaforge diagnostics
```

---

## Example Usage

```bash
# Create a new environment with Python 3.11 and scientific packages
$ nebulaforge create data-science --python 3.11 --packages numpy pandas scikit-learn

# Install a package into an existing environment
$ nebulaforge install data-science matplotlib

# Run a full security scan
$ nebulaforge diagnostics
🔧 Running security diagnostics...
🔧 Security Diagnostics Report
============================================================
📊 General Status: EXCELLENT (Score: 100/100)
🔐 Profile: Medium Security (medium)

# Back up an environment
$ nebulaforge backup --create data-science
✅ Backup created successfully: backup_data-science_20260607_101530.yaml

# Change to a stricter security profile
$ nebulaforge config --security-level high
✅ Security level changed to: high

# Enable production mode (full read-only mode)
$ nebulaforge config --production-mode on
✅ Production mode enabled

# Medium and stricter profiles require explicit confirmation for mutations
$ nebulaforge create my-project --python 3.11 --yes
$ nebulaforge remove my-project --yes
```

---

## Available Commands

| Command                        | Description                              |
|--------------------------------|------------------------------------------|
| `nebulaforge`                  | Launch TUI interface                     |
| `nebulaforge interactive`      | Interactive step-by-step CLI             |
| `nebulaforge list`             | List all environments                    |
| `nebulaforge create <name>`    | Create a new secure environment (`--yes` at medium+) |
| `nebulaforge install <env>`    | Install packages into an environment (`--yes` at medium+) |
| `nebulaforge remove <env>`     | Remove an environment, with backup (`--yes` at medium+) |
| `nebulaforge info <env>`       | Show environment details                 |
| `nebulaforge update <env>`     | Update packages in an environment (`--yes` at medium+) |
| `nebulaforge backup`          | Manage backups (`--create <env>`, `--list`, `--restore <file> --yes`) |
| `nebulaforge diagnostics`      | Run full security diagnostics            |
| `nebulaforge audit`            | View the audit trail                     |
| `nebulaforge config`           | Change security level (`--security-level`) or production mode (`--production-mode on/off`) |

---

## Security Profiles

| Profile   | Allowed Commands       | Protected Envs¹          | Confirmation³ | Max Timeout | Reserved Names Blocked at Creation² |
|-----------|------------------------|--------------------------|---------------|-------------|--------------------------------------|
| Low       | conda, mamba, pip      | base, root               | No            | 600s        | base, root                           |
| Medium    | conda, mamba, pip      | base, root, prod         | Yes           | 300s        | + system, conda                      |
| High      | conda, mamba           | base, root, prod         | Yes           | 180s        | + prod                               |
| Paranoid  | conda only             | base, root, prod         | Yes           | 120s        | + env, venv                          |

¹ *Protected environments* cannot be deleted or modified. The exact set depends on the profile:
Low protects `base` and `root`; Medium and stricter also protect `prod`. Write operations such as
install, update, clone target, import, restore, or creation with a protected name are rejected.
Read-only operations such as backup and export remain available.
² Names rejected when creating a new environment; each row accumulates the rows above it (enforced by `SecurityValidator` through each profile's `validation_strictness`).
³ The profile's `require_confirmation` policy flag. Medium and stricter profiles require an explicit confirmation: the TUI and interactive CLI prompt for it, and the one-shot CLI requires `--yes` (it exits with code `2` when confirmation is missing). Protected environments and production mode are hard denials and cannot be overridden by confirmation.

Each profile also adjusts `validation_strictness` for environment names, package names, and filenames — stricter profiles reject more permissive patterns and block more reserved keywords.

---

## Security Highlights

- **Protected environments** (at minimum `base` and `root`; `prod` from Medium up) cannot be deleted or modified; reserved names such as `system` or `conda` are additionally blocked at creation time depending on the profile
- **Production mode** is disabled by default; when enabled it makes every mutating operation read-only (create, install, update, delete, clone target, import, and restore). Toggle it with `nebulaforge config --production-mode on|off`
- **Confirmation policy**: the medium, high, and paranoid profiles require explicit confirmation for mutations. The TUI and interactive CLI prompt; the one-shot CLI requires `--yes` and exits with code `2` when confirmation is missing
- **Strict package name validation** with progressive malware keyword blocking (9 terms at Medium, 18 at High, 27 at Paranoid)
- **Command runner hardening**: `shell=False`, argument-level dangerous pattern detection, conda flag blocking per profile
- **Path-traversal protection** for backup/export filenames and restore paths. Environment imports are strictly sandboxed to the configured backup directory; symlinks and `..` segments that resolve outside it are rejected and audit-logged
- **Atomic restore**: a temporary environment is built and swapped in; the live target is moved to a unique quarantine name and rolled back on any failure, so a broken restore never destroys an environment
- **Cryptographic chain integrity** on every audit entry (SHA-256 chain)
- **Backup integrity** verified via separate `.sha256` sidecar files
- **Encrypted credential and data stores** with PBKDF2 key derivation (600,000 iterations)
- **Session tokens** generated with `secrets.token_urlsafe(32)` and masked in status/listing output
- **Secure file permissions** (`0o600` for config, logs, backups, and encrypted data; `0o700` for directories)
- **Dependency scanning** in CI via Bandit (SAST) and Safety (CVE), both blocking; documented Safety exceptions live in `.safety-policy.yml` with an expiry date

---

## Architecture

NebulaForge is built around a layered security model. The high-level flow is:

```
TUI / CLI / Interactive CLI
        |
        v
   EnvironmentService   <-- single source of truth for operations
        |
        v
   SecurityManager      <-- central orchestrator
        |
   +----+----+----+----+----+----+----+
   |    |    |    |    |    |    |    |
Config Audit Backup Deps Validator Crypto Session
```

The `EnvironmentService` is the only public API exposed to the interfaces; the `SecurityManager` orchestrates all sub-components; each sub-component has a single, well-defined responsibility.

---

## Testing & Quality

```bash
# Run the full test suite
uv run --no-sync pytest tests/ -v

# With coverage (fails below the 60% project gate)
uv run --no-sync pytest tests/ -v --cov=nebulaforge --cov-report=term-missing

# Linting and type checking
uv run --no-sync flake8 nebulaforge/ --count --select=E9,F63,F7,F82 --show-source --statistics
uv run --no-sync ruff check nebulaforge/
uv run --no-sync mypy nebulaforge/ --ignore-missing-imports
uv run --with bandit bandit -r nebulaforge/

# Real-Conda smoke test (skipped by default; isolated envs/pkgs dirs, no network packages)
NEBULAFORGE_RUN_CONDA_INTEGRATION=1 uv run --no-sync pytest tests/test_conda_integration.py -v
```

CI enforces the critical `flake8` checks (`E9,F63,F7,F82`), `mypy`, the full test suite on
Python 3.12, a 60% coverage floor (`--cov-fail-under=60`, Codecov patch target 80%), and blocking
Bandit/Safety scans. `ruff` (configured in `pyproject.toml`) is the recommended style linter for
local development. The real-Conda smoke test runs in the manual `Conda Integration` workflow
(`.github/workflows/integration.yml`) and is part of the release checklist.

---

## Project Structure

```
nebulaforge/                # repository root
├── nebulaforge/            # installable package
│   ├── core/               # Core security logic
│   │   ├── security_manager.py
│   │   ├── security_validator.py
│   │   ├── security_models.py
│   │   ├── config_manager.py
│   │   ├── audit_logger.py    # SHA-256 chain integrity
│   │   ├── backup_manager.py  # SHA-256 verified backups
│   │   ├── encrypted_store.py # Fernet + PBKDF2
│   │   ├── secure_store.py    # Encrypted key-value store with TTL
│   │   ├── secrets.py         # Encrypted credential store
│   │   ├── session.py         # Cryptographic session tokens
│   │   ├── dependency_checker.py
│   │   ├── environment_service.py
│   │   ├── error_handler.py
│   │   ├── interactive_cli.py
│   │   ├── cli_helpers.py
│   │   └── secure_diagnostics.py
│   ├── interfaces/         # User-facing layers
│   │   ├── tui.py          # Rich-based TUI
│   │   └── cli.py          # argparse CLI
│   ├── plugins/            # Extensible plugin system
│   │   ├── base_plugin.py
│   │   ├── security_scanner.py
│   │   └── health_check.py
│   ├── utils/              # Cross-cutting helpers
│   │   ├── command_runner.py  # Hardened subprocess wrapper
│   │   ├── formatters.py
│   │   ├── helpers.py
│   │   ├── version_utils.py
│   │   └── vulnerability_db.py
│   └── config/             # Security profile definitions
│       └── security_profiles.py
├── tests/                  # 27 test files, 318 tests (real-Conda test skipped by default)
├── .github/workflows/      # CI, manual Conda integration, and security scanning
├── .safety-policy.yml      # Documented, expiring Safety exceptions
├── pyproject.toml
├── uv.lock
├── .python-version
├── README.md               # English (default)
├── README.es.md            # Spanish
└── SECURITY.md             # Vulnerability reporting policy
```

---

## Contributing

Contributions are welcome. Please open an issue to discuss substantial changes before submitting a pull request. Briefly:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Install dev dependencies (`uv sync --extra dev`)
4. Make your changes and add tests
5. Run the test suite (`uv run --no-sync pytest tests/ -v`)
6. Run the linters (`uv run --no-sync flake8 nebulaforge/ --select=E9,F63,F7,F82`, `uv run --no-sync ruff check nebulaforge/`, and `uv run --no-sync mypy nebulaforge/ --ignore-missing-imports`)
7. Open a Pull Request

---

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not open a public issue for a security vulnerability.

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Author

**Morphilab**  
[GitHub](https://github.com/Morphilab)
