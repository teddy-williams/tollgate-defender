#!/usr/bin/env bash
# Build an offline install bundle for air-gapped machines (run this on a machine WITH internet).
#
#   scripts/make-offline-bundle.sh                                   # for this machine's OS/Python
#   scripts/make-offline-bundle.sh --platform win_amd64 --python 3.12   # for Windows x64 + Python 3.12
#   scripts/make-offline-bundle.sh --docker                          # also include a Docker image tarball
#
# Platforms: manylinux2014_x86_64, manylinux2014_aarch64, win_amd64, macosx_11_0_arm64, macosx_10_9_x86_64
set -euo pipefail
PLATFORM=""; PYVER=""; DOCKER=0; OUT="offline-bundle"
while [ $# -gt 0 ]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2 ;;
    --python) PYVER="$2"; shift 2 ;;
    --docker) DOCKER=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
cd "$(dirname "$0")/.."
VERSION="$(python3 -c 'import tollgate; print(tollgate.__version__)')"
rm -rf "$OUT" && mkdir -p "$OUT/wheelhouse"
BUILDENV="$(mktemp -d)"; trap 'rm -rf "$BUILDENV" build ./*.egg-info' EXIT   # isolated: never touches your system Python
python3 -m venv "$BUILDENV"; PY="$BUILDENV/bin/python"
"$PY" -m pip install -q build
"$PY" -m build --wheel --outdir "$OUT/wheelhouse"
WHEEL="$(ls "$OUT"/wheelhouse/tollgate_defender-*.whl)"
ARGS=()
if [ -n "$PLATFORM" ]; then ARGS+=(--platform "$PLATFORM" --only-binary=:all: --implementation cp); fi
if [ -n "$PYVER" ]; then ARGS+=(--python-version "$PYVER"); fi
"$PY" -m pip download "$WHEEL[all]" -d "$OUT/wheelhouse" "${ARGS[@]}"
if [ "$DOCKER" = 1 ]; then
  docker build -t "tollgate:$VERSION" .
  docker save "tollgate:$VERSION" | gzip > "$OUT/tollgate-image-$VERSION.tar.gz"
fi
cp docs/INSTALL.md "$OUT/INSTALL.md"
cat > "$OUT/README.txt" <<TXT
Tollgate $VERSION offline bundle.
Install (Python 3.10+):  python -m venv .venv ; activate it ; pip install --no-index --find-links wheelhouse "tollgate-defender[all]"
Docker image (if present):  docker load -i tollgate-image-$VERSION.tar.gz
Full instructions: INSTALL.md
TXT
tar czf "tollgate-offline-$VERSION${PLATFORM:+-$PLATFORM}.tar.gz" "$OUT"
echo "Bundle ready: tollgate-offline-$VERSION${PLATFORM:+-$PLATFORM}.tar.gz ($(du -sh "$OUT" | cut -f1) unpacked)"
