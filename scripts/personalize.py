#!/usr/bin/env python3
"""Fill in the placeholders before publishing:  python scripts/personalize.py --name "Jane Doe" --github janedoe --contact security@example.org"""
import argparse
import pathlib

ap = argparse.ArgumentParser()
ap.add_argument("--name", required=True, help="copyright holder / author name")
ap.add_argument("--github", required=True, help="GitHub username or organisation")
ap.add_argument("--contact", required=True, help="security contact email")
args = ap.parse_args()

repl = {"<YOUR NAME>": args.name, "<your-github-username>": args.github, "<your-security-contact>": args.contact}
root = pathlib.Path(__file__).resolve().parent.parent
skip = {".git", ".venv", "node_modules", "__pycache__", "dist", "build"}
changed = 0
for path in root.rglob("*"):
    if not path.is_file() or skip & set(path.parts) or path.suffix in {".zip", ".png", ".gz", ".whl"} or path.name == "personalize.py":
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    new = text
    for old, val in repl.items():
        new = new.replace(old, val)
    if new != text:
        path.write_text(new, encoding="utf-8")
        changed += 1
        print("updated", path.relative_to(root))
print(f"{changed} file(s) updated")
