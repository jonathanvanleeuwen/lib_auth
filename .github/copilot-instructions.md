# lib_auth - AI Coding Agent Instructions

---
## 📋 Generic Code Standards (Reusable Across All Projects)

### Code Quality Principles

**DRY (Don't Repeat Yourself)**
- No duplicate code - extract common logic into reusable functions/classes
- If you copy-paste code, you're doing it wrong
- Shared utilities belong in `utils/` or helper modules

**CLEAN Code**
- **C**lear: Code intent is obvious from reading it
- **L**ogical: Functions do one thing, follow single responsibility principle
- **E**asy to understand: Junior developers should be able to review it
- **A**ccessible: Avoid clever tricks; prefer explicit over implicit
- **N**ecessary: Every line serves a purpose; no dead code

**Production-Grade Simplicity**
- Code must be production-ready (robust, tested, maintainable)
- Use the simplest solution that solves the problem completely
- Complexity is a last resort, not a goal
- **Target audience**: Code should be readable by junior software developers/data scientists

### Comments & Documentation Philosophy

**No Commented-Out Code**
- Never commit commented code blocks - use version control instead
- Delete unused code; git history preserves it if needed

**Docstrings: Only When Necessary**
- If code requires a docstring to be understood, it's probably too complex
- Refactor for clarity first, document as a last resort
- When used, docstrings explain **WHY**, not **HOW**
- Good function/variable names eliminate most documentation needs

**Comment Guidelines**
- Explain business logic rationale, not implementation mechanics
- Document non-obvious constraints or requirements
- If a comment explains what code does, rewrite the code to be self-explanatory
- Example:
  ```python
  # ❌ BAD: Explains what (obvious from code)
  # Loop through users and add to list
  for user in users:
      result.append(user)

  # ✅ GOOD: Explains why (non-obvious business rule)
  # Cache expires after 1 hour due to API rate limits
  cache_ttl = timedelta(hours=1)
  ```

### Code Organization Standards

**Function Design**
- Functions should do **one thing** and do it well
- If a function has "and" in its description, it likely does too much
- Keep functions short (aim for <20 lines when possible)

**Import Management**
- Keep `__init__.py` files minimal - only version info and essential public API
- Prefer explicit imports: `from module.submodule import specific_function`
- Avoid importing from `__init__.py` in application code
- Long import statements are fine; they show dependencies clearly

**Separation of Concerns**
- Each module/class has a single, well-defined responsibility
- Business logic separated from I/O, API layers, and presentation
- Configuration separated from implementation

**Readability First**
- Variable names should be descriptive: `user_count` not `uc`
- Consistent naming conventions throughout the project
- Code is read 10x more than written - optimize for reading

### Development Tooling Standards

**Python Version**
- Follow Python syntax for the version specified in `pyproject.toml` (currently >=3.11)
- Backwards compatibility is NOT required - use modern Python features

**Package & Environment Management**
- Use `uv` for all virtual environment operations
- Always create venvs with: `uv venv .venv`
- Install dependencies with: `uv pip install -e ".[dev]"`

**Code Quality Tools**
- **ruff**: Primary linter and formatter (replaces black, isort, flake8)
  - Format code: `ruff format .`
  - Check code: `ruff check .`
  - Fix issues: `ruff check --fix .`
- Follow ruff's formatting style (no manual formatting needed)

**Testing**
- **pytest**: Only testing framework to use
- Always run tests in the `.venv` environment
- Execute with: `.\.venv\Scripts\python.exe -m pytest -v` (picks up config from pyproject.toml)
- Coverage reports generated in `reports/htmlcov/`

**Test Organization**
- **Unit tests** (`tests/unit/`): Test individual functions/classes in isolation
  - No HTTP calls, no FastAPI TestClient
  - Test pure logic: token operations, hashing, role resolution, provider config
  - Fast, focused, deterministic
  - File naming: `test_<module_name>.py` (e.g., `test_token_operations.py`)

- **Integration tests** (`tests/integration/`): Test components working together
  - Use FastAPI TestClient for HTTP interactions
  - Test full authentication flows, OAuth routers, endpoints
  - Mock external dependencies (OAuth provider APIs)
  - File naming: `test_<feature>.py` (e.g., `test_auth_dependency.py`, `test_oauth_router.py`)

- **Fixtures** (`conftest.py`): Shared test fixtures and configuration
  - Create fixtures for common test data (settings, API keys, mock requests)
  - Keep fixtures reusable and well-documented
  - Use `@pytest.fixture` decorator

**Test Quality Standards**
- **Readable**: Test names describe what is being tested (e.g., `test_api_key_auth_admin_access`)
- **Isolated**: Each test is independent, can run in any order
- **Focused**: One assertion per concept, multiple assertions per test is fine if related
- **Coverage**: Aim for >90% code coverage
- **Organized**: Group related tests in the same file
  - Token creation/verification → `test_token_operations.py`
  - API key hashing → `test_api_key_utils.py`
  - OAuth providers → `test_oauth_providers.py`
  - Full auth flows → `test_auth_dependency.py`

**Running Tests**
```bash
pytest                               # Run all tests with coverage
pytest tests/unit/                   # Run only unit tests
pytest tests/integration/            # Run only integration tests
pytest tests/unit/test_token_operations.py  # Run specific test file
pytest -k "test_api_key"            # Run tests matching pattern
pytest -v                            # Verbose output
```

### Documentation Requirements

**Always Update README.md**
- When adding new features, **immediately update README.md** with:
  - Usage examples showing the new functionality
  - Configuration options if applicable
  - Output/artifact descriptions
  - Integration instructions if needed
- When changing how artifacts are generated (models, figures, metrics):
  - Update the "Generated Outputs" section
  - Include directory structure examples
  - Document file formats and contents
- README must stay synchronized with code - outdated docs are worse than no docs

**Documentation Standards**
- Examples must be runnable (copy-paste should work)
- Include both CLI and programmatic usage where applicable
- Show realistic use cases, not toy examples
- Explain WHY features exist, not just HOW to use them

### Meta-Instruction
**Keep these instructions updated** based on chat interactions when patterns emerge or decisions are made that should guide future development.

---

## Development Workflow

**Setup**
```bash
uv venv .venv                    # Create virtual environment with uv
uv pip install -e ".[dev]"      # Install package and dev dependencies
pre-commit install              # Install pre-commit hooks
pre-commit run --all-files      # Run hooks on all files (REQUIRED before first commit)
```

**Code Quality**
```bash
ruff format .                   # Format all code
ruff check .                    # Check for issues
ruff check --fix .              # Auto-fix issues
```

**Testing**
```bash
pytest                          # Run all tests with coverage (reports/htmlcov/)
pytest -v                       # Verbose output
```

**Building & Distribution**
```bash
python setup.py bdist_wheel     # Creates wheel in dist/
```

## CI/CD Pipeline

**On Pull Request to main**
- Pre-commit hooks (ruff, isort, trailing-whitespace, etc.)
- pytest with coverage

**On Merge to main** (requires `RELEASE_TOKEN` secret)
1. Coverage report generated and committed to README
2. Semantic versioning based on commit messages:
   - `fix:` → patch (1.0.x)
   - `feat:` → minor (1.x.0)
   - `BREAKING CHANGE:` → major (x.0.0)
3. Build wheel and publish to GitHub Releases

**Commit Message Format** (for semantic release)
```
<type>: <description>

[optional body]
```
Types: `fix`, `feat`, `docs`, `chore`, `test`, `refactor`

## Code Conventions

**Module Structure**
```
src/lib_auth/
├── __init__.py           # Minimal - version + public API only
├── core/                 # Core business logic
└── utils/                # Shared utilities
```

**Public API** (exported in `__init__.py`)
- Only export what external users need
- Keep internal implementation details private

**Testing Patterns**
- Unit tests verify individual component behavior
- Coverage target: >90% (see reports/htmlcov/)

## Common Pitfalls

- **Don't commit directly to main** - pre-commit hook will block it
- **Missing tests** - All new functionality requires tests
- **Circular imports** - Keep module dependencies acyclic
