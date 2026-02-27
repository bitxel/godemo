# Contributing to demoit

Thanks for contributing to `demoit`.

## Development Setup

### Gateway (Go)

```bash
cd gateway
go test ./...
```

### Python SDK

```bash
cd sdk/python
python3 -m pip install -e .
python3 -m unittest discover -s tests
```

## Pull Request Process

1. Fork and create a topic branch from `main`.
2. Keep changes focused and include tests for behavior changes.
3. Run Go and Python tests locally before opening a PR.
4. Use clear PR descriptions:
   - what changed
   - why it changed
   - how it was tested
5. Wait for CI to pass and at least one maintainer review.

## Commit Style

- Prefer small, atomic commits.
- Use imperative tense in commit titles (example: `add ws timeout handling`).

## Release Process

- Create a version tag like `v0.2.0`.
- Push the tag to trigger `.github/workflows/release.yml`.
- The workflow builds:
  - `demoit-gateway` linux binary
  - Python source distribution and wheel
- Maintainers can then review and publish the generated GitHub Release.

## Reporting Security Issues

Please do not open public issues for sensitive vulnerabilities.
Use the process in `SECURITY.md`.
