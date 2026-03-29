# Contributing to VISaR

Thank you for wanting to contribute to VISaR! We welcome contributions from the community and are grateful for your support.

If you have found a bug, have a feature request, or want to improve the documentation, please open an issue on our [GitHub Issues page](https://github.com/AtLongLastAnalytics/visar/issues) with as much detail as possible.

---

## Getting Started

1. Fork the repository and clone it locally.
2. From the project root, install all dependencies (including dev tools):

   ```
   uv sync
   ```

3. Create a feature branch:

   ```
   git checkout -b feature/your-feature-name
   ```

---

## Code Style

- Follow the [PEP 8](https://peps.python.org/pep-0008/) style guide for Python.
- Keep code clear, concise, and well-documented using Google-style docstrings.
- Use type hints on all function signatures.

---

## Linting

We use [ruff](https://github.com/astral-sh/ruff) for linting and formatting. Run it before submitting a pull request:

```
uv run ruff check .
uv run ruff format .
```

The CI pipeline runs `ruff check` automatically on every push and pull request.

---

## Testing

We use Python's built-in `unittest` framework. All new functions should be accompanied by unit tests in the appropriate file under `tests/`. We aim for close to 100% test coverage.

Run the full test suite locally before submitting:

```
uv run python -m unittest discover -s tests -v
```

---

## Pull Requests

When submitting a pull request:

- Include a clear description of what changed and why.
- Ensure all tests pass locally.
- Ensure `ruff check .` reports no issues.
- Keep changes focused — one concern per pull request.

---

## License

By contributing to this project, you agree that your contributions will be licensed under the [Apache-2.0 License](../LICENSE).
