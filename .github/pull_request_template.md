## What and why

## Checklist
- [ ] `ruff check .` and `python -m pytest -q` pass
- [ ] Tests added/updated (use the synthetic builders in `tests/helpers.py`; **no real malware samples or live C2 URLs**)
- [ ] Detection changes: considered false positives and said how I checked
- [ ] New YARA rules have `meta: description` and `severity`, and I wrote them myself or have the right to contribute them under Apache-2.0
- [ ] Docs / CHANGELOG updated if behaviour changed
