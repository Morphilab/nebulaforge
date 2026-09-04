# NebulaForge

**Forge secure, auditable Conda environments with enterprise-grade security**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://github.com/Morphilab/nebulaforge/actions/workflows/tests.yml/badge.svg)](https://github.com/Morphilab/nebulaforge/actions)
[![codecov](https://codecov.io/gh/Morphilab/nebulaforge/branch/main/graph/badge.svg)](https://codecov.io/gh/Morphilab/nebulaforge)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/Morphilab/nebulaforge/releases)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow)](https://github.com/PyCQA/bandit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000)](https://github.com/astral-sh/ruff)
[![Mypy checked](https://img.shields.io/badge/mypy-checked-blue)](http://mypy-lang.org/)
[![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen)](https://github.com/Morphilab/nebulaforge/graphs/commit-activity)

---

## Why NebulaForge?

Managing Conda environments securely and reproducibly is challenging. NebulaForge solves this by providing **enterprise-grade security controls**, full audit trails with cryptographic chain integrity, secure backups with SHA-256 verification, vulnerability scanning, and a modern Rich-based terminal interface — all in one powerful, extensible tool.

Whether you are an individual developer who cares about reproducibility, a data-science team that needs audit trails, or a security-conscious organization that needs strict environment isolation, NebulaForge has a security profile for you.

---

## Key Features

- **Three Interfaces**: Rich-based TUI, interactive step-by-step CLI, and traditional argparse CLI
- **Four Security Profiles**: Low, Medium, High, and Paranoid — each with progressively stricter controls
- **Cryptographic Audit Trail**: SHA-256 hash chain on every audit entry, tamper-evident
- **Secure Backups**: Automatic pre-operation backups with SHA-256 checksum verification
- **Vulnerability Scanner**: Built-in detection of 20 known vulnerable packages (CVE-aware)
- **Plugin System**: Extensible architecture with `SecurityScanner` and `HealthCheck` built-ins
- **Encrypted Storage**: Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 (600k iterations) for credentials and secrets
- **Session Management**: Cryptographically secure tokens with TTL and max-sessions enforcement
- **Strict Validation**: Malware keyword blocking, dangerous pattern detection, profile-aware strictness
- **Multi-Python Support**: Tested on Python 3.8 through 3.12

---
## ⚠️ AI Disclosure / Divulgación de IA

**English:**  
This project was developed with assistance from artificial intelligence tools. Given the automated nature of some components, users are advised to review and test the code independently before integrating it into their own systems.

**Español:**  
Este proyecto fue desarrollado con asistencia de herramientas de inteligencia artificial. Dada la naturaleza automatizada de algunos componentes, se recomienda que los usuarios revisen y prueben el código independientemente antes de integrarlo en sus propios sistemas.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/Morphilab/nebulaforge.git
cd nebulaforge
pip install -e .

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
[OK] Conda installed
[OK] No known vulnerable packages
[WARN] 2 outdated packages detected
[INFO] Security score: 92/100

# Back up an environment
$ nebulaforge backup --create data-science
✅ Backup created successfully: backup_data-science_20260607_101530.yaml

# Change to a stricter security profile
$ nebulaforge config --security-level high
✅ Security level changed to: high
```

---

## Available Commands

| Command                        | Description                              |
|--------------------------------|------------------------------------------|
| `nebulaforge`                  | Launch TUI interface                     |
| `nebulaforge interactive`      | Interactive step-by-step CLI             |
| `nebulaforge list`             | List all environments                    |
| `nebulaforge create <name>`    | Create a new secure environment          |
| `nebulaforge install <env>`    | Install packages into an environment     |
| `nebulaforge remove <env>`     | Remove an environment (with backup)      |
| `nebulaforge info <env>`       | Show environment details                 |
| `nebulaforge update <env>`     | Update packages in an environment        |
| `nebulaforge backup [env]`     | Manage backups (`--create`, `--list`, `--restore`) |
| `nebulaforge diagnostics`      | Run full security diagnostics            |
| `nebulaforge audit`            | View the audit trail                     |
| `nebulaforge config`           | Change security level (`--security-level`)|

---

## Security Profiles

| Profile   | Allowed Commands       | Protected Envs¹          | Confirmation | Max Timeout | Reserved Names Blocked at Creation² |
|-----------|------------------------|--------------------------|--------------|-------------|--------------------------------------|
| Low       | conda, mamba, pip      | base, root               | No           | 600s        | base, root                           |
| Medium    | conda, mamba, pip      | base, root, prod         | Yes          | 300s        | + system, conda                      |
| High      | conda, mamba           | base, root, prod         | Yes          | 180s        | + prod                               |
| Paranoid  | conda only             | base, root, prod         | Yes          | 120s        | + env, venv                          |

¹ *Protected Envs* cannot be deleted or modified and require confirmation for other operations.
² Names rejected when creating a new environment; each row accumulates the rows above it (enforced by `SecurityValidator` through each profile's `validation_strictness`).

Each profile also adjusts `validation_strictness` for environment names, package names, and filenames — stricter profiles reject more permissive patterns and block more reserved keywords.

---

## Security Highlights

- **Protected environments** (`base`, `root`, `prod`) cannot be deleted or modified and require explicit confirmation; reserved names such as `system` or `conda` are additionally blocked at creation time depending on the profile
- **Production mode** blocks delete operations by default and requires confirmation for install/update/clone
- **Strict package name validation** with progressive malware keyword blocking (9 terms at Medium, 18 at High, 27 at Paranoid)
- **Command runner hardening**: `shell=False`, argument-level dangerous pattern detection, conda flag blocking per profile
- **Path-traversal protection** in backup and import operations (sandboxed to backup directory)
- **Cryptographic chain integrity** on every audit entry (SHA-256 chain)
- **Backup integrity** verified via separate `.sha256` sidecar files
- **Encrypted credential and data stores** with PBKDF2 key derivation (600,000 iterations)
- **Session tokens** generated with `secrets.token_urlsafe(32)`, masked in logs
- **Secure file permissions** (`0o600` for data, `0o700` for directories)
- **Dependency scanning** in CI via Bandit (SAST) and Safety (CVE)

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
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=nebulaforge --cov-report=term-missing

# Linting and type checking
flake8 nebulaforge/ --count --select=E9,F63,F7,F82 --show-source --statistics
ruff check nebulaforge/
mypy nebulaforge/ --ignore-missing-imports
bandit -r nebulaforge/
```

CI enforces the critical `flake8` checks (`E9,F63,F7,F82`) on every push; `ruff` (configured in `pyproject.toml`) is the recommended style linter for local development.

All tests pass across **Python 3.8, 3.9, 3.10, 3.11 and 3.12** in CI.

---

## Project Structure

```
nebulaforge/
├── core/                  # Core security logic
│   ├── security_manager.py
│   ├── security_validator.py
│   ├── security_models.py
│   ├── config_manager.py
│   ├── audit_logger.py    # SHA-256 chain integrity
│   ├── backup_manager.py  # SHA-256 verified backups
│   ├── encrypted_store.py # Fernet + PBKDF2
│   ├── secure_store.py    # Encrypted key-value store with TTL
│   ├── secrets.py         # Encrypted credential store
│   ├── session.py         # Cryptographic session tokens
│   ├── dependency_checker.py
│   ├── environment_service.py
│   ├── error_handler.py
│   ├── interactive_cli.py
│   ├── cli_helpers.py
│   └── secure_diagnostics.py
├── interfaces/            # User-facing layers
│   ├── tui.py             # Rich-based TUI
│   └── cli.py             # argparse CLI
├── plugins/               # Extensible plugin system
│   ├── base_plugin.py
│   ├── security_scanner.py
│   └── health_check.py
├── utils/                 # Cross-cutting helpers
│   ├── command_runner.py  # Hardened subprocess wrapper
│   ├── formatters.py
│   ├── helpers.py
│   ├── version_utils.py
│   └── vulnerability_db.py
├── config/                # Security profile definitions
│   └── security_profiles.py
└── tests/                 # 26 test files, 260 tests
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow. Briefly:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Install dev dependencies (`pip install -e ".[dev]"`)
4. Make your changes and add tests
5. Run the test suite (`pytest tests/ -v`)
6. Run the linters (`flake8 nebulaforge/ --select=E9,F63,F7,F82` and `ruff check nebulaforge/`)
7. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Author

**Morphilab**  
[GitHub](https://github.com/Morphilab)
