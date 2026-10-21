# Writing and contributing detection rules

Tollgate has three detection layers you can extend without touching code.

1. **Indicators (intel DB):** exact hashes, imphash, domains, URLs, IPs. Best for known samples and infrastructure.
2. **YARA rules:** structure and behaviour in any file type. Best for families and techniques.
3. **Regex string rules:** a quick regex over strings extracted from PE files (`tollgate intel rule-add`). Use for a fast stop-gap; prefer YARA.

## YARA conventions
```yara
rule Zeta_Loader_Beacon : pe loader
{
    meta:
        description = "ZetaLoader C2 beacon format"          // shown as the finding title
        severity    = "high"                                  // critical | high | medium | low   (default: high)
        family      = "ZetaLoader"                            // optional
        reference   = "https://example.org/write-up"
        author      = "you"
        date        = "2026-10-16"
    strings:
        $a = "zeta_c2_beacon" ascii wide
        $b = { 8B 45 08 33 C9 }
    condition:
        uint16(0) == 0x5A4D and all of them
}
```
- **`severity = "critical"` is decisive: the verdict becomes Malicious on its own.** Use it only for rules with essentially no false positives.
  Findings are named `YARA_<rule>` (or `INTEL_YARA_<rule>` for critical).
- Prefer specific strings and conditions; anchor on file type (`uint16(0) == 0x5A4D` for PE, `%PDF-` near the start for PDF).
- Avoid expensive patterns (unbounded regex, many `nocase wide` strings). Rules time out after 30 seconds per file.
- `include` is rejected for uploaded rules; the `pe`, `math`, `hash` modules are fine.
- Test a rule: `tollgate yara add rule.yar` validates and installs it; then scan a **synthetic** file containing the marker.

Install: UI (Intel & rules), `tollgate yara add`, API `/api/rules/yara`, or drop `.yar` files in `$TOLLGATE_HOME/rules/`.
Invalid files are reported by `tollgate yara list` and never disable the other rule files.

## Contributing rules to the project
Open a pull request adding a `.yar` file to `tollgate/rules/`. Requirements:
- Written by you, or under a license compatible with Apache-2.0 that you have the right to contribute. Do not paste rules from
  commercial or restrictively licensed sets.
- `meta` with `description` and `severity`; `reference` where there is a public write-up.
- A note in the PR on **false-positive testing** (what benign files you tried) and expected hit scope.
- No malware samples, live C2 addresses or credentials in the PR. For tests use synthetic bytes (see `tests/helpers.py`).
- Generic hygiene rules are welcome; very narrow single-sample rules belong in your own `rules/` folder or a shared intel feed.

## Indicators
Types: `sha256 md5 sha1 imphash domain url ip`. Domains match the domain and all subdomains. Use `--severity critical` for
confirmed-malicious infrastructure (decisive), lower severities for suspicious-but-uncertain. Always record `--family` and
`--source` so analysts can see where a verdict came from, and remove false positives with `tollgate intel remove`.
