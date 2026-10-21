# Contributing to Tollgate

Thanks for helping defenders. Bug reports, false-positive reports, detection rules, docs and code are all welcome.

## Ground rules
- **Never commit real malware, live C2 addresses, credentials or customer data**, in code, tests, issues or rules. Tests use synthetic
  files built in memory (`tests/helpers.py` builds tiny harmless PE files; other types are a few crafted bytes).
- Be kind: see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security problems go through [SECURITY.md](SECURITY.md), not public issues.
- By contributing you agree your work is licensed under Apache-2.0 and that you have the right to contribute it.

## Development setup
```bash
git clone https://github.com/teddy-williams/tollgate-defender.git && cd tollgate-defender
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[all,dev]"
python -m pytest -q          # tests
ruff check .                 # lint
tollgate serve               # run the UI locally
```
Python 3.10+ is supported; CI runs 3.10-3.13.

## Making a change
1. Open an issue first for anything non-trivial (new analyzer, new endpoint, scoring change).
2. Branch, change, add tests. Detection changes need a test that triggers the finding **and** one showing a benign look-alike does not.
3. Run tests and lint. Update `docs/` and `CHANGELOG.md` if behaviour changes.
4. Open a pull request using the template. Explain false-positive considerations for any detection.

## Code guidelines
- Analyzers only **parse bytes**: never execute, import or render sample content. Bound memory and time on every parser.
- Everything shown in the UI must go through text nodes (no `innerHTML`); anything that touches the network must go through `redirects.py`.
- Findings have stable `rule_id`s, a severity, and a detail string that helps an analyst decide. Keep titles short.
- Keep dependencies minimal; discuss before adding one.

## Detection rules
See [docs/RULES.md](docs/RULES.md). YARA rules go in `tollgate/rules/` with `meta: description` and `severity`; say how you checked for false positives.

## Releases (maintainers)
Update `tollgate/__init__.py` and `CHANGELOG.md`, commit, then `git tag vX.Y.Z && git push --tags`. The release workflow checks the tag
matches the version, builds the wheel/sdist, offline wheelhouses and Docker image, pushes the image to GHCR and creates the GitHub Release.
