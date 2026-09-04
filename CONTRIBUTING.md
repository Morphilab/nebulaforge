# Contributing to NebulaForge

Thank you for your interest in contributing to NebulaForge!

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure all tests pass (`pytest tests/ -v`)
5. Update documentation if needed
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Development Setup

```bash
git clone https://github.com/Morphilab/nebulaforge.git
cd nebulaforge
pip install -e ".[dev]"
pytest tests/ -v
```

## Code Guidelines

- All user-facing strings must be in English (code and comments)
- Follow PEP 8 style; CI enforces the critical flake8 checks (`flake8 nebulaforge/ --select=E9,F63,F7,F82`) and `ruff check nebulaforge/` should pass locally
- Add type hints where possible
- Keep security as the top priority
- Write clear commit messages

## Reporting Issues

Please use the [GitHub Issues](https://github.com/Morphilab/nebulaforge/issues) page.

---
