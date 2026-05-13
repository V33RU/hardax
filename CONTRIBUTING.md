# Contributing to HARDAX

Thanks for your interest in improving HARDAX.

## Workflow

1. **All changes land via a Pull Request to `dev`.** Direct pushes to `main`
   are blocked — `main` is reserved for releases.
2. Fork the repo (external contributors) or create a feature branch off
   `dev` (maintainers).
3. Make focused changes. Keep PRs small.
4. Open a PR targeting **`dev`**, not `main`.
5. Maintainers periodically merge `dev` into `main` and cut a release.

## Adding a Security Check

HARDAX checks live in `commands/*.json`. To add one:

```json
{
  "category": "SYSTEM",
  "label": "Short human-readable name",
  "command": "shell command to run on the device",
  "safe_pattern": "regex that indicates a SAFE result",
  "level": "info | warning | critical",
  "description": "What this check detects and why it matters"
}
```

Optional fields: `empty_is_safe`, `null_is_safe`, `requires_output`,
`why`, `risk_if_fail`, `nist_800_53`, `id`.

**Regex validity matters.** Invalid `safe_pattern` regexes will emit a
warning at startup and silently degrade to substring matching, which can
flip a SAFE/CRITICAL classification. Test your regex.

## Running Locally

```bash
# After pip install
hardax --version
hardax --category SYSTEM --severity critical

# From a source checkout without installing
python3 -m hardax --version
python3 -m hardax --category SYSTEM --severity critical
```

Python 3.11+ required.

## Commit Style

- One logical change per commit
- Imperative mood ("Add X", "Fix Y", not "Added X")
- Reference issue numbers where relevant

## Reporting Bugs

Use the issue templates. For security issues, see [SECURITY.md](SECURITY.md).
