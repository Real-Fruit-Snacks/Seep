# Contributing to Seep

Thank you for your interest in contributing to Seep! This document provides guidelines and instructions for contributing.

## Development Environment Setup

### Prerequisites

- **Python** 3.9+ with pip
- **Git** for version control

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/Seep.git
cd Seep

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run linting
ruff check server/
```

## Code Style

All code must pass the following checks before submission:

- **Linting:** `ruff check server/` -- zero warnings allowed
- **Tests:** `python -m pytest tests/ -v` -- all tests must pass

Run both before submitting a PR:

```bash
ruff check server/
python -m pytest tests/ -v
```

## Testing Requirements

- All existing tests must continue to pass: `python -m pytest tests/ -v`
- New features must include tests
- New PowerShell checks must include corresponding Python test coverage

## Pull Request Process

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Test thoroughly:**
   ```bash
   ruff check server/
   python -m pytest tests/ -v
   ```

4. **Push** your branch and open a Pull Request against `main`.

5. **Describe your changes** in the PR using the provided template.

6. **Respond to review feedback** promptly.

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                          |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation changes                |
| `style`    | Formatting, no code change           |
| `refactor` | Code restructuring, no behavior change |
| `test`     | Adding or updating tests             |
| `ci`       | CI/CD changes                        |
| `chore`    | Maintenance, dependencies            |
| `perf`     | Performance improvements             |

### Examples

```
feat(agent): add registry secrets enumeration check
fix(catalog): handle missing SHA256 in tool definitions
docs: update OPSEC table with CLM detection details
ci: add PowerShell syntax validation to CI pipeline
```

### Important

- Do **not** include AI co-author signatures in commits.
- Keep commits focused on a single logical change.

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub.
