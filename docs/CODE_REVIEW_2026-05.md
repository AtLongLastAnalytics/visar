# VISaR 1.1.0 — Independent Code Review

**Reviewer:** Claude (Anthropic), via Cowork desktop mode
**Date:** 2026-05-26
**Scope:** Full codebase at commit on disk (src/, tests/, .github/, docs/, pyproject.toml)
**Goal of review:** Assess whether VISaR is production-ready and what is required to take it from "hobby project" to something sellable into defence and aviation teams.

---

## 1. Headline verdict

VISaR 1.1.0 is a **competent, well-structured hobby/OSS project**, but it is **not yet production-ready for defence or aviation customers**. The gap is not primarily about code quality — the code is above average for the maturity of the project. The gap is about **supply-chain assurance, evidence/traceability, secrets management, air-gap operation, and ecosystem coverage** — exactly the dimensions defence and aviation buyers scrutinise before they let a tool touch their software approval pipeline.

The encouraging news: most of the missing pieces are already named in your ROADMAP.md ("Short-Term" and "Long-Term" sections cover ~70% of what defence customers will demand). With ~1–2 quarters of focused work and a clear pivot away from "open-source utility" framing toward "compliance evidence tool," VISaR can credibly enter pilot conversations with the defence/aviation primes.

Roughly:

| Dimension | Hobby project | OSS production | Defence/aviation pilot-ready |
|---|---|---|---|
| Code structure | ✅ Above this bar | ✅ Above this bar | ⚠️ Needs packaging + entry points |
| Tests | ✅ | ⚠️ No coverage gate, no integration tests | ❌ No security tests, no fuzz, no traceability matrix |
| Security hygiene | ✅ Token in `.env`, list-form subprocess | ⚠️ No secret-manager integration, no SAST | ❌ No FIPS pathway, no air-gap, no signed releases |
| Output usefulness | ✅ CSV/JSON/HTML | ⚠️ No CVE/CVSS, no SBOM input | ❌ No formal evidence report, no signing |
| Supply chain | ⚠️ uv.lock present | ❌ No SLSA, no Sigstore, no SBOM-of-VISaR | ❌ |
| Compliance docs | ⚠️ SECURITY.md exists | ❌ No threat model, no DFD, no DEFCON 658 statement | ❌ |

---

## 2. What's working well

These are the strengths to preserve, not change:

- **Clean `src/` layout, single responsibility per module.** `helpers/` separates Docker, OSV, dashboard, helper, and logging concerns. This is what reviewers expect.
- **Docstrings are excellent.** Google-style, complete on every function. Worth keeping the bar high here — defence reviewers read every docstring.
- **Type hints are used throughout** (with caveats below).
- **Subprocess invocations use list args, not `shell=True`.** This eliminates the shell-injection vector you noted you'd fixed in the v1.1 roadmap. Good.
- **HTML escaping in the dashboard is done correctly** — both the JS `esc()` for cell content and the `</` → `<\/` replacement on the embedded JSON to prevent script tag breakout (`dashboard_funcs.py:625`). This is the kind of thing a security reviewer will check first; you got it right.
- **The CI pipeline is real** — uv with `--frozen`, ruff lint + format check, unit tests under coverage, minimum `contents: read` permissions block. The `actions/checkout@v4` and `astral-sh/setup-uv@v5` are current.
- **Dependabot is configured** for both GitHub Actions and pip ecosystems.
- **Apache-2.0 licence** is defence-compatible (GPL is often a blocker; MIT is fine; Apache-2.0 is preferred because of explicit patent grant — exactly what defence procurement counsel want to see).
- **`SECURITY.md` exists with explicit in-scope and out-of-scope**, including token leakage and HTML-dashboard injection. Most hobby projects don't bother.
- **Retry helper (`retry_call`) is generalised** and used for both Docker and OSV — good factoring.

---

## 3. Issues that are bugs or correctness problems

These are real defects to fix before any external pilot.

### 3.1 `extract_vulnerability_ids` only matches PYSEC and GHSA
`src/helpers/helper_funcs.py:85`

```python
vuln_id_pattern = r"(PYSEC-\w{4}-\w{2,5}(?: /)?|GHSA-\w{4}-\w{4}-\w{4})"
```

For a tool aimed at "evaluating any open-source library before ingestion," this is too narrow. OSV indexes at least: `CVE-`, `OSV-`, `RUSTSEC-`, `RUBYSEC-`, `GO-`, `MAL-`, `GHSA-`, `PYSEC-`, `BIT-`, `NPM-SA-`, `DLA-`, `DSA-`, `USN-`, `ASB-A-`. If your target users are scanning Python repos *only*, today's regex is roughly OK; defence customers evaluating C/C++, Rust, Go, JS frameworks will see empty reports and silently mistrust the tool.

**Action:** Widen the regex *or* (preferred) parse OSSF Scorecard JSON output rather than regexing the text rendering. Scorecard already emits structured findings via `--format json` — using that removes the regex entirely.

### 3.2 `fetch_aliases` catches the wrong exception types
`src/helpers/osv_funcs.py:59`

```python
except (ConnectionError, TimeoutError) as e:
```

These are Python builtins — `requests` raises `requests.exceptions.ConnectionError`, `requests.exceptions.Timeout`, `requests.exceptions.RequestException`. They will not be caught by this clause and will fall through to the bare `except Exception` below, which is masked as "Unexpected error." This is the kind of silent reliability issue that erodes confidence after a few hundred runs.

**Action:** Either use `requests.exceptions.RequestException` (as `fetch_single_detail` correctly does on `osv_funcs.py:138`) or `requests.exceptions.ConnectionError, requests.exceptions.Timeout`.

> **Resolved 2026-05-26:** Replaced `(ConnectionError, TimeoutError)` with `(requests.exceptions.ConnectionError, requests.exceptions.Timeout)` in `osv_funcs.py:59`, consistent with how `fetch_single_detail` handles network errors.

### 3.3 `extract_vulnerability_ids` return type is wrong
`src/helpers/helper_funcs.py:69`

Declared as `Optional[List[str]]` but the function never returns `None` — it always returns a list. Misleading hints aside, this matters for `mypy --strict`, which defence customers will run.

> **Resolved 2026-05-26:** Changed signature and docstring from `Optional[List[str]]` to `List[str]` in `helper_funcs.py:69`. `Optional` was removed from the import as it is no longer used by this function.

### 3.4 `verify_github_token` has no `timeout`
`src/helpers/helper_funcs.py:245`

```python
response = requests.get(f"{GITHUB_CONFIG['BASE_URL']}/user", headers=headers)
```

You added timeouts to OSV calls in v1.1 (good). The GitHub call was missed. Same issue applies — a stalled connection hangs the prereq check indefinitely.

> **Resolved 2026-05-26:** Added `timeout=30` to the `requests.get` call in `verify_github_token` (`helper_funcs.py:245`).

### 3.5 `subprocess.run(["docker", "info"], ...)` has no timeout
`src/helpers/docker_funcs.py:43` and `:139`

A misbehaving Docker daemon (paused, suspended container runtime, network issue) can leave `docker info` blocked. Add `timeout=30` and handle `subprocess.TimeoutExpired`.

> **Resolved 2026-05-26:** Added `timeout=30` to `check_docker_isrunning` (`docker_funcs.py:43`) and `timeout=300` to `run_docker_command` (`docker_funcs.py:139`). Both now handle `subprocess.TimeoutExpired` with an appropriate error log. The longer timeout for `run_docker_command` reflects that a full Scorecard scan of a large repo can legitimately take several minutes.

### 3.6 `config.py` validates env at import time
`src/config.py:45–48`

```python
if GITHUB_CONFIG["GITHUB_TOKEN"] is None:
    raise EnvironmentError(...)
```

This raises at *import* time. Side effects on import are a smell — they mean `config` cannot be imported anywhere (including in tests, dashboard.py for a future offline review mode, or by humans reading docs in REPL) without the token. Move validation into `run_prerequisite_checks` or a `validate_config()` function called from `main()` and `scan_single_repository()` only.

This was also why earlier test revisions needed `sys.path.insert(0, "./src")` and careful env setup.

> **Resolved 2026-05-26:** Removed the import-time `raise EnvironmentError` from `config.py` and replaced it with a `validate_config()` function. `main.py` now imports and calls `validate_config()` immediately after argument parsing, before any scan work begins. `config` can now be imported freely in tests and tooling without a live token present.

### 3.7 GitHub token leaks into Docker process listing
`src/helpers/docker_funcs.py:107`

```python
command = ["docker", "run", "--rm", "-e", f"GITHUB_AUTH_TOKEN={github_token}", ...]
```

Anyone with `docker ps -a --no-trunc` or `docker inspect` access on the host (root, dockerd group) can read the token from the container's environment. This is well-known in defence threat models — credentials in argv/env are a finding under most STIG checklists.

**Action:** Use `--env-file <tempfile>` (with `0600` perms, cleaned up in `finally`), or pipe via stdin, or write to a temp file mounted read-only. Easiest: an `--env-file` written to a tmpfs path with `os.umask(0o077)`.

### 3.8 Token verification runs on every repo in a batch
`src/main.py:297` → `run_prerequisite_checks` is inside `scan_single_repository`, which is called per URL inside the batch loop at `main.py:412`.

For a 200-repo batch this is 200 calls to `api.github.com/user`. Slow and consumes rate budget. Verify once before the batch loop.

### 3.9 Sequential batch is a soft limit for the defence use case
A typical defence "approved software list" review covers hundreds of components. At 2–5 minutes per repo, a 200-repo batch is 7–17 hours. Concurrency (with a bounded pool, respecting GitHub primary/secondary rate limits) needs to be in your near-term plan.

### 3.10 Filename construction does not sanitise
`src/helpers/helper_funcs.py:96`

`format_filename` would happily produce `20260526-..-..-bar` if it ever saw a URL that bypassed `validate_github_url`. Defence reviewers will demand defence-in-depth: sanitise here *as well* (whitelist `[A-Za-z0-9._-]`, reject anything else).

> **Resolved 2026-05-26:** Hardened `format_filename()` in `src/visar/helpers/helper_funcs.py:97` to parse repository paths into segments, reject empty paths, reject `.` and `..`, and enforce a safe filename allowlist (`[A-Za-z0-9._-]`) on each segment before joining them with hyphens. Trailing slashes are now normalized instead of producing a trailing hyphen. Added unit tests in `tests/test_helper_funcs.py` covering normalized trailing slashes and rejection of empty paths, dot segments, and unsafe characters.

---

## 4. Architecture & packaging gaps

### 4.1 VISaR is not actually installable
The README requires users to `cd src/` because the modules use sibling-relative imports (`from config import ...`, `import helpers.docker_funcs as dof`). There is no `__init__.py` at `src/`, no `src/visar/` package, no `[project.scripts]` entry point in `pyproject.toml`, no console-script. So:

- `uv tool install visar` won't work.
- `pipx install visar` won't work.
- `python -m visar` won't work.
- Anyone packaging this for an internal artifact repository (Artifactory, Nexus, internal PyPI mirror) will have to rewrite the import structure.

This is the single biggest "feels like a hobby project" signal in the codebase.

**Action:**
- Move `src/*.py` and `src/helpers/*.py` into `src/visar/` and `src/visar/helpers/`.
- Add `src/visar/__init__.py` with `__version__`.
- Add to `pyproject.toml`:
  ```toml
  [project.scripts]
  visar = "visar.main:main"
  visar-dashboard = "visar.dashboard:main"
  ```
- Rewrite imports as `from visar.config import ...` or use explicit-relative `from .config import ...`.
- Update tests to import via the installed package (drop `sys.path.insert`).
- Drop the README's "must run from src/" caveat. This will close the largest credibility gap.

> **Resolved 2026-05-26:** Created `src/visar/` package with `__init__.py` (exports `__version__`). Moved all source files into `src/visar/` and `src/visar/helpers/`. Rewrote all internal imports to explicit-relative style (`.config`, `..config`, `.helpers.logger_config`, etc.). Fixed `__file__`-based path calculations in `config.py`, `dashboard.py`, and `logger_config.py` to account for the extra directory level. Added `[build-system]` (hatchling) and `[tool.hatch.build.targets.wheel]` to `pyproject.toml` so `uv sync` installs the package into the venv. Added `[project.scripts]` entry points (`visar` and `visar-dashboard`). Updated all 5 test files: removed `sys.path.insert(0, "./src")`, updated import paths to `visar.helpers.*` / `visar.main`, updated all `@patch()` strings accordingly, and removed the now-unused `import sys`. Old flat files in `src/` (config.py, main.py, dashboard.py, helpers/) need to be deleted manually — they are no longer referenced.

### 4.2 Tests depend on cwd
Every test file has `sys.path.insert(0, "./src")` (e.g. `tests/test_helper_funcs.py:32`). This works only when `unittest discover` is run from the project root. Symptom of the packaging gap above.

> **Resolved 2026-05-26:** All test files now import via the installed `visar` package and no longer modify `sys.path`. Verified by running the full suite from inside the `tests/` directory with `..\\.venv\\Scripts\\python.exe -m unittest discover -s . -v`, which passes without requiring the project root as the current working directory.

### 4.3 Module-level `requests.Session()` is never closed
`src/helpers/osv_funcs.py:32`

Minor, but in a batch with 1000+ OSV requests this matters. Also no `urllib3.util.retry.Retry` adapter — `retry_call` reinvents this at the function level, but a proper adapter would handle 429s and Retry-After correctly. OSV's API does rate-limit, and defence customers will batch-scan.

> **Resolved 2026-05-26:** Replaced the module-global OSV `requests.Session()` with a `_create_session()` factory in `src/visar/helpers/osv_funcs.py` that mounts an `HTTPAdapter` with `urllib3.util.retry.Retry` configured for transient network failures and HTTP 429/5xx responses. `fetch_aliases()` and `fetch_single_detail()` now create and close owned sessions when called directly, while `fetch_details()` and `update_idlist()` reuse a single scoped session for batch work and close it when finished. Updated `tests/test_osv_funcs.py` to validate the new session lifecycle and batch-session reuse behavior.

### 4.4 No structured exceptions
Almost every error path is `except Exception`. There is no `VisarError` hierarchy. After-the-fact incident review (which defence requires) is much harder when the only signal is a string in a log.

**Action:** Introduce a small exception hierarchy (`VisarError`, `VisarPrerequisiteError`, `VisarDockerError`, `VisarAPIError`, `VisarOutputError`) and let exit_with_error map them to distinct exit codes (currently everything is `1`).

> **Resolved 2026-05-26:** Added `src/visar/exceptions.py` with a structured VISaR exception hierarchy (`VisarError`, `VisarPrerequisiteError`, `VisarDockerError`, `VisarDataError`, `VisarAPIError`, `VisarOutputError`). `src/visar/helpers/helper_funcs.py` now maps these exception types to stable process exit codes in `exit_with_error()`, while `src/visar/main.py` passes typed exceptions through the main pipeline for prerequisite, Docker, data-transformation, API, and output failures. Updated `tests/test_helper_funcs.py` and `tests/test_main.py` to validate both the exit-code mapping and the error-category wiring.

### 4.5 Parallel-list anti-pattern
`vuln_ids: List[str], details: List[str], severities: List[str]` is threaded through the entire pipeline. A length mismatch between the three is silently lost on `zip()`. Convert to a dataclass `Finding` (id, severity, details, plus future fields: cve, cvss, ecosystem, source) and pass a single `List[Finding]`. This is also how the formal evidence report on the roadmap will be cleaner to implement.

> **Resolved 2026-05-26:** Added `src/visar/models.py` with a shared `Finding` dataclass and refactored the internal pipeline to pass `List[Finding]` instead of parallel `vuln_ids/details/severities` lists. `src/visar/helpers/osv_funcs.py` now returns findings from `fetch_details()`, `src/visar/main.py` threads findings through `call_osv_api()` and `write_output()`, `src/visar/helpers/helper_funcs.py` writers persist findings while preserving the existing CSV/JSON schema, and `src/visar/helpers/dashboard_funcs.py` reads and prepares dashboard datasets from findings rather than zipping separate lists. Updated `tests/test_osv_funcs.py`, `tests/test_helper_funcs.py`, `tests/test_main.py`, and `tests/test_dashboard_funcs.py` to validate the single-list finding flow end-to-end.

### 4.6 Logging is unstructured text
Plain text logs are unparseable by Splunk/Elastic/Sentinel without bespoke regex. Defence SOCs expect JSON or CEF. Adopt `python-json-logger` or stdlib JSON formatter for the file handler, keep the human-readable console handler.

> **Resolved 2026-05-26:** Added a stdlib-backed `JsonLogFormatter` in `src/visar/helpers/logger_config.py` and applied it only to the rotating file handler created by `setup_logger()`. File logs are now emitted as structured JSON with timestamp, level, logger, message, and call-site metadata, while the stdout console handler keeps the existing human-readable text format. Added `tests/test_logger_config.py` to validate both the JSON payload shape and the file-vs-console formatter split.

### 4.7 Dashboard pulls Google Fonts from a CDN
`src/helpers/dashboard_funcs.py:633–635`

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Manrope...">
```

Two problems for defence:
1. Many evidence artifacts will be opened on machines without internet access — the dashboard's typography will silently degrade, which is fine, but a reviewer will note "this artifact has an external dependency at view-time."
2. Some classified networks deny *.googleapis.com outright.

**Action:** Embed the font file as base64 in CSS, *or* drop the webfont and use the system stack you already have as fallback. The dashboard should be 100% self-contained (no preconnects, no external link tags).

> **Resolved 2026-05-26:** Removed the Google Fonts `preconnect` and stylesheet tags from `src/visar/helpers/dashboard_funcs.py` and switched the dashboard body typography to a local system font stack. The generated dashboard HTML is now fully self-contained at view time with no external font fetches. Added a focused assertion in `tests/test_dashboard_funcs.py` to ensure `write_multi_dashboard()` does not emit `fonts.googleapis.com`, `fonts.gstatic.com`, or `preconnect` tags.

### 4.8 No Content-Security-Policy in the dashboard
The dashboard inlines JS and embeds JSON. Even with the escape logic, a strict CSP meta tag would prove (to a reviewer) that nothing executes from origins other than the document. Add:

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; font-src data:;">
```

Then drop the Google Fonts link to keep CSP clean.

> **Resolved 2026-05-26:** Added a strict `Content-Security-Policy` meta tag to the dashboard HTML emitted by `src/visar/helpers/dashboard_funcs.py` with `default-src 'none'`, inline-only script and style allowances, and `img-src`/`font-src` restricted to self or data URLs as applicable. This now makes the exported dashboard artifact explicitly self-contained at the browser policy level, complementing the 4.7 removal of external font dependencies. Added a focused test in `tests/test_dashboard_funcs.py` to assert the exact CSP tag in the generated HTML.

---

## 5. The defence/aviation gap — what's actually missing

This is the most important section. The items here are not bugs; they are the *table-stakes* for defence and aviation evaluation. Treat this as your pre-pilot punch list.

### 5.1 Supply-chain assurance

**What buyers look for:**
- A signed release (Sigstore / cosign, or signed git tags + signed release archives).
- SLSA provenance attestation (Level 2 minimum for serious procurement).
- A CycloneDX or SPDX SBOM **for VISaR itself**, published with each release.
- Reproducible builds (uv.lock gets you most of the way; document the toolchain pinning).
- The OSSF Scorecard score for VISaR, published in the README. (Ironic if your own tool isn't scored.)
- Dependency review on PRs (`actions/dependency-review-action`).

**Where you are:** none of the above. You have `uv.lock` (good) and Dependabot (good).

**Smallest credible step:** Add a `release.yml` GitHub Actions workflow that builds the wheel, signs it with `sigstore-python`, generates a CycloneDX SBOM (`uv pip compile` + `cyclonedx-py`), and uploads all three to the GitHub Release.

### 5.2 Secrets handling

**What buyers look for:**
- Pluggable secret sources: env, file, HashiCorp Vault, Azure Key Vault, AWS Secrets Manager, GCP Secret Manager.
- Token never appears in argv/env of child processes.
- Token never appears in logs at any level (verify with a fuzz test).
- Configurable token scope (some teams want fine-grained PATs or GitHub Apps with installation tokens).

**Where you are:** `.env` only, token passed via Docker `-e`. See §3.7.

**Smallest credible step:** Abstract token retrieval behind a `TokenProvider` interface with `EnvTokenProvider` as the default; add docs (not necessarily code) describing how to plug in Vault/KeyVault.

### 5.3 Air-gap / offline mode

**What buyers look for:**
- A tool that can run with **zero** outbound connections except to internal mirrors.
- Local OSV database (already on your long-term roadmap — good).
- Locally-mirrored Scorecard image (you already document `docker pull`).
- Configurable OSV API base URL so a customer can point at their internal OSV mirror.

**Where you are:** named on the roadmap, not built. This is the single highest-leverage feature for defence/aviation. Without it, **classified networks cannot run VISaR at all.**

### 5.4 Compliance-grade output

**What buyers look for:**
- CVE IDs and CVSS base scores (already on roadmap).
- Repository risk score (already on roadmap).
- A formal HTML/PDF evidence report with: scan metadata, tool version, scan date, hash of the scanned input, input source, severity summary, full findings, attestation block at the end (e.g. "Scanned by VISaR v1.1.0 against OSV DB snapshot YYYY-MM-DD"). Already on roadmap.
- A way to **sign** the evidence artifact (detached signature file, or an X.509 / PGP signature embedded).
- Outputs in CycloneDX VEX format for integration with downstream vuln management (Anchore, Dependency-Track, GitHub Advanced Security).

**Where you are:** CSV/JSON/HTML, no signing, no metadata block. Roadmap is correct in direction.

### 5.5 Source coverage

**What buyers look for:**
- GitHub.com **and** GitHub Enterprise Server / GitHub Enterprise Cloud (FedRAMP / IL5).
- GitLab.com, GitLab Dedicated, self-managed GitLab.
- Azure DevOps (huge in defence primes).
- Bitbucket Server.
- Private repositories.
- Local directory scanning (already on roadmap — good).
- SBOM ingestion (already on roadmap — good).

**Where you are:** public GitHub only.

### 5.6 Standards alignment statements

Even if you don't certify, defence buyers want to see *named* alignment in your docs. Add a `docs/COMPLIANCE.md` covering at minimum:

- **NIST SP 800-218 (SSDF)** — which practices VISaR implements (PS.3.1 archive & protect each release, RV.1.1/1.3 vulnerability disclosure, PW.4.4 acquire software securely, etc.).
- **EO 14028 / OMB M-22-18 self-attestation form** — how VISaR helps a producer meet sections 4(e)(i–x).
- **NIST SP 800-161r1 (C-SCRM)** — how VISaR fits as a third-party-component evaluation control.
- **CISA Secure-by-Design pledge** — easy public commitment to make; reviewers notice it.
- **UK MOD DEFCON 658 / JSP 440** — if you intend to sell UK side, statement of fit.
- **DO-326A / ED-202A airworthiness security** — for aviation, a one-page note on where VISaR fits in the security risk assessment (TSRA) pipeline.

You won't certify against any of these — you're a tool, not a system — but referencing them by number in your docs signals literacy to the buyer.

### 5.7 Cryptography statement

Defence customers will ask: "is this FIPS 140-3 compliant?" Strictly, *VISaR* doesn't implement crypto — `requests` does, via OpenSSL. So the truthful answer is:

> "VISaR delegates all TLS and cryptographic operations to the host's OpenSSL via the `requests` library. When run on a FIPS-mode RHEL 9 / Ubuntu Pro FIPS host, all TLS connections to GitHub and OSV use FIPS-validated cryptographic modules. VISaR adds no cryptography of its own."

Put exactly that in `docs/COMPLIANCE.md`. It is short, true, and answers the question without overclaiming.

### 5.8 Threat model & DFD

Defence procurement loves diagrams. Produce a one-page **STRIDE-style threat model** showing:
- Actors (analyst, attacker on host, attacker on network, malicious OSS author).
- Data flows (GitHub API, OSV API, Docker, filesystem).
- Trust boundaries.
- Controls (token scope, list-form subprocess, HTML escaping, etc.).

This is two days of work and will land in pre-sales conversations more often than the README does.

### 5.9 Static analysis & security scanning of VISaR itself

Add to CI:
- `pip-audit` (or `uv pip audit` if/when supported) — fails on known CVEs in your deps.
- `bandit` — Python SAST.
- `semgrep --config p/python --config p/security-audit` — broader SAST.
- `gitleaks` — secret scanning on every PR.
- `actions/dependency-review-action@v4` — blocks PRs that introduce known-vuln deps.
- `codeql-action` with the python query pack — free for public repos.
- Trivy or Grype on the wheel + a generated SBOM.

This is the most embarrassing gap: a vulnerability scanner that doesn't scan itself.

### 5.10 Reproducibility & SBOM
- Publish a CycloneDX SBOM with every GitHub Release.
- Include a `make sbom` (or `uv run cyclonedx-py environment`) target.
- Document the verification command in the README ("To verify VISaR has not been tampered with: `cosign verify-blob ...`").

---

## 6. Test suite assessment

- **Volume:** ~2,600 lines of tests against ~2,200 lines of source. Healthy ratio.
- **Structure:** one class per function under test — clean.
- **Mocking:** appropriate use of `unittest.mock.patch`.

**Gaps:**

1. **No coverage threshold gate in CI.** You run `coverage run -m unittest` but never `coverage report --fail-under=N`. Defence customers will ask the coverage number — make it part of CI policy at, say, 90%.
2. **No integration tests with a real Docker daemon.** Even a single end-to-end test against a known small public repo, run nightly (not on every PR), would catch real regressions.
3. **No security/fuzz tests.** Run `extract_vulnerability_ids` against hypothesis-generated junk, the URL validator against the [adversarial URL corpus](https://github.com/cure53/H5SC), and the dashboard generator against malicious payloads in detail strings.
4. **No mutation testing.** `mutmut` or `cosmic-ray` will reveal whether your tests are actually asserting behaviour. Defence reviewers occasionally ask for mutation score.
5. **Tests previously relied on `sys.path.insert(0, "./src")`.** This was resolved by the packaging work in §4.1/§4.2; keep new tests importing through `visar.*` only.

---

## 7. Documentation assessment

Strong:
- README is well above the OSS norm — quick start, prerequisites, CLI reference, architecture diagram, scan duration estimate, exit codes. Don't shrink any of this.
- ROADMAP.md is genuinely useful and shows defence-aware thinking.
- SECURITY.md scope is well drawn.

Missing for the defence pivot:
- `docs/ARCHITECTURE.md` — beyond the README diagram, a real DFD with trust boundaries.
- `docs/THREAT_MODEL.md` — see §5.8.
- `docs/COMPLIANCE.md` — see §5.6 and §5.7.
- `docs/RELEASE.md` — how releases are built, signed, and verified.
- `docs/MAINTAINERS.md` — who can release, key handling, vulnerability triage SLA (already partially in SECURITY.md, but separate).
- `CODE_OF_CONDUCT.md` at root — small thing, expected for OSS due-diligence checklists.
- Root-level `CHANGELOG.md` is gitignored at the repo root (`.gitignore` line 39) but exists in `docs/`. Convention is root-level. Fix the .gitignore exclusion.

---

## 8. Minor code quality observations

- Several `vuln_ids: Any` annotations in `main.py:138, 154, 177, 195` should be `List[str]`.
- `Optional[List[str]]` return type on `extract_vulnerability_ids` is wrong (§3.3).
- Mix of `open(...)` and `path.open(...)` — fine, but pick one for consistency.
- Module docstrings repeat author/date/version. As you scale, keep this in `__init__.py` only.
- Comments include date "2026-03" — that's fine, but every file having an author block is heavy; convention in production is a top-of-file SPDX line and nothing else.

Recommended single-line file headers (replacing the current 14-line block):

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) AtLongLast Analytics LLC
```

This is the format GitHub Linguist, Open Source Insights, and most enterprise SCA tools expect.

---

## 9. Suggested execution plan (90-day pivot)

If your goal is "be in pilot conversations with a defence prime in 90 days," here is a plausible sequence. Items are roughly in dependency order.

**Weeks 1–2 — credibility plumbing**
- Repackage as installable `visar` package with `[project.scripts]` entry points (§4.1).
- Drop "must `cd src/`" caveat from README.
- Fix bugs in §3.1–3.6.
- Add `pip-audit`, `bandit`, `gitleaks`, `codeql` to CI.
- Add coverage threshold to CI.

**Weeks 3–4 — supply chain**
- Sigstore signing of releases.
- CycloneDX SBOM published with each release.
- Run OSSF Scorecard on visar; publish badge.
- Reproducible build documented; `release.yml` workflow.

**Weeks 5–6 — outputs that count**
- CVE & CVSS enrichment from OSV.
- Formal evidence report (HTML + PDF) with hash, version, attestation block.
- Detached signature on evidence artifacts (cosign).
- Risk score field in CSV/JSON.

**Weeks 7–8 — air-gap & private**
- Configurable OSV API base URL.
- Local OSV cache mode (offline scan).
- Private GitHub repo support (token scope upgrade with backward compat).
- GitHub Enterprise Server (host configurable).

**Weeks 9–10 — compliance package**
- `docs/THREAT_MODEL.md` (STRIDE + DFD).
- `docs/COMPLIANCE.md` aligning to NIST SP 800-218, 800-161, EO 14028.
- `docs/SECURE_DEPLOYMENT.md` (how a defence team runs VISaR safely).
- One-page commercial deck: problem, control, evidence outputs.

**Weeks 11–12 — pilot prep**
- Local-directory scan (§roadmap).
- SBOM ingestion (CycloneDX).
- Concurrency on batch scans, with proper Retry/backoff.
- First pilot partner. Offer custom report templates as a paid service from day one — this is your wedge into "custom solutions."

---

## 10. Bottom line

This is a real piece of software, not a weekend script. Most hobby Python projects fail on packaging, testing, error handling, *and* docs; VISaR fails only on packaging and on the things that don't show up in any normal OSS checklist (supply chain, air-gap, signed evidence). Those things are exactly what makes defence and aviation pilots possible — so closing them isn't waste; it *is* the product differentiation.

The pivot from "free open-source utility" to "compliance evidence tool for regulated supply chains" is plausible and probably the right go-to-market. Keep the OSS core, sell the compliance scaffolding, custom report templates, on-prem integrations, and air-gap deployment as paid offerings around it.

---

*End of review.*
