#!/usr/bin/env bash
# secretsift full verification. Run from anywhere:   bash scripts/verify.sh
#
# What it checks (and prints one PASS / FAIL / SKIP line for each at the end):
#   - install with dev extras (installs pytest, httpx, ruff, mypy)
#   - the full unittest suite (httpx tests stop being skipped once httpx is installed)
#   - pytest run + the real pytest plugin (the `secretsift` fixture)
#   - ruff, ruff format, mypy
#   - wheel build, install into a fresh virtualenv, `secretsift` and `sift` commands, demo
#   - the CLI end to end in a temp directory
#   - every examples/*/secretsift.yaml validates
#   - optional: other Python versions   ALL_PYTHONS=1 bash scripts/verify.sh
#   - optional: dependency audit        AUDIT=1 bash scripts/verify.sh
#
# Offline machine? SKIP_INSTALL=1 skips every step that needs the network.
# Send the final summary (and the output of any FAIL block) back to get it fixed.

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
cd "$ROOT" || exit 1
PY="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
RESULTS=()

pass_or_fail() { # name, exit-code
  if [ "$2" -eq 0 ]; then RESULTS+=("PASS  $1"); else RESULTS+=("FAIL  $1"); fi
}
skip() { RESULTS+=("SKIP  $1  ($2)"); }
header() { printf '\n=== %s\n' "$1"; }
have_module() { "$PY" -c "import $1" >/dev/null 2>&1; }
have_tool() { "$PY" -m "$1" --version >/dev/null 2>&1; }

# Run the CLI from the source tree (works installed or not).
sift() { PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" "$PY" -m secretsift "$@"; }

header "Python"
"$PY" --version

# ---------------------------------------------------------------- install
if [ "${SKIP_INSTALL:-0}" = "1" ]; then
  skip "install with dev extras" "SKIP_INSTALL=1"
else
  header "Install (editable, with dev extras)"
  "$PY" -m pip install -q -e ".[dev]"
  pass_or_fail "install with dev extras" $?
fi

# ---------------------------------------------------------------- unittest
header "unittest suite"
PYTHONPATH="$ROOT/src" "$PY" -m unittest discover -s tests -t . -q
pass_or_fail "unittest suite" $?
if have_module httpx; then
  RESULTS+=("INFO  httpx is installed: its transport tests ran for real")
else
  RESULTS+=("INFO  httpx not installed: 2 transport tests were skipped")
fi

# ---------------------------------------------------------------- pytest
if have_module pytest; then
  header "pytest run of the same tests"
  PYTHONPATH="$ROOT/src" "$PY" -m pytest -q -p no:cacheprovider
  pass_or_fail "pytest run" $?

  header "pytest plugin (needs the package installed so the entry point exists)"
  mkdir -p "$TMP/plug"
  cat >"$TMP/plug/test_clean.py" <<'PYEOF'
def test_clean(secretsift):
    key = secretsift.secret("customer_api_key", "synthetic_api_key")
    assert key
PYEOF
  cat >"$TMP/plug/test_leaky.py" <<'PYEOF'
import logging


def test_leaky(secretsift):
    key = secretsift.secret("customer_api_key", "synthetic_api_key")
    logging.getLogger("demo").warning("key=%s", key)
PYEOF
  (cd "$TMP/plug" && PYTHONPATH="$ROOT/src" "$PY" -m pytest -q -p no:cacheprovider test_clean.py)
  clean_rc=$?
  (cd "$TMP/plug" && PYTHONPATH="$ROOT/src" "$PY" -m pytest -q -p no:cacheprovider test_leaky.py)
  leaky_rc=$?
  if [ "$clean_rc" -eq 0 ] && [ "$leaky_rc" -eq 1 ]; then
    RESULTS+=("PASS  pytest plugin (clean test passes, leaky test is failed by the fixture)")
  else
    RESULTS+=("FAIL  pytest plugin (clean rc=$clean_rc expected 0, leaky rc=$leaky_rc expected 1;"
              "      if the fixture is not found run: python -m pip install -e .)")
  fi
else
  skip "pytest run" "pytest not installed"
  skip "pytest plugin" "pytest not installed"
fi

# ---------------------------------------------------------------- lint and types
header "ruff check"
if have_tool ruff; then "$PY" -m ruff check . ; pass_or_fail "ruff check" $?; else skip "ruff check" "ruff not installed"; fi
header "ruff format --check"
if have_tool ruff; then "$PY" -m ruff format --check . ; pass_or_fail "ruff format --check" $?; else skip "ruff format" "ruff not installed"; fi
header "mypy"
if have_tool mypy; then "$PY" -m mypy ; pass_or_fail "mypy (strict)" $?; else skip "mypy" "mypy not installed"; fi

# ---------------------------------------------------------------- build + clean install
if [ "${SKIP_INSTALL:-0}" = "1" ]; then
  skip "wheel build and clean install" "SKIP_INSTALL=1"
else
  header "Build wheel and install it into a fresh virtualenv"
  ok=0
  "$PY" -m pip install -q build || ok=1
  [ $ok -eq 0 ] && "$PY" -m build --wheel --outdir "$TMP/dist" . || ok=1
  [ $ok -eq 0 ] && "$PY" -m venv "$TMP/venv" || ok=1
  [ $ok -eq 0 ] && "$TMP/venv/bin/pip" install -q "$TMP"/dist/*.whl || ok=1
  if [ $ok -eq 0 ]; then
    mkdir -p "$TMP/clean" && cd "$TMP/clean" || exit 1
    "$TMP/venv/bin/secretsift" version || ok=1
    "$TMP/venv/bin/sift" version || ok=1
    "$TMP/venv/bin/secretsift" demo >/dev/null 2>&1
    demo_rc=$?
    { [ "$demo_rc" -le 1 ] && ls "$TMP"/clean/secretsift-reports/*.html >/dev/null 2>&1; } || ok=1
    cd "$ROOT" || exit 1
  fi
  pass_or_fail "wheel build + clean install + secretsift/sift commands + demo" $ok
fi

# ---------------------------------------------------------------- CLI end to end
header "CLI end to end (temp directory)"
mkdir -p "$TMP/cli" && cd "$TMP/cli" || exit 1
ok=0
sift version >/dev/null || ok=1
sift init >/dev/null || ok=1
sift validate >/dev/null || ok=1
sift test --report json,html,junit,terminal --no-color >/dev/null; rc=$?
[ "$rc" -eq 1 ] || { echo "expected exit 1 (the starter config contains one intentional leak), got $rc"; ok=1; }
for f in secretsift-report.json secretsift-report.html secretsift-report.xml; do
  [ -f "secretsift-reports/$f" ] || { echo "missing report: $f"; ok=1; }
done
sift report secretsift-reports/secretsift-report.json --format html --output "$TMP/cli/again.html" >/dev/null || ok=1
sift diff secretsift-reports/secretsift-report.json secretsift-reports/secretsift-report.json >/dev/null || ok=1
sift doctor >/dev/null || ok=1
sift providers >/dev/null || ok=1
cd "$ROOT" || exit 1
pass_or_fail "CLI: version init validate test report diff doctor providers" $ok

# ---------------------------------------------------------------- examples
header "examples validate"
ok=0
for cfg in examples/*/secretsift.yaml; do
  if sift validate --config "$cfg" >/dev/null 2>&1; then echo "ok   $cfg"; else echo "FAIL $cfg"; ok=1; fi
done
pass_or_fail "all examples/*/secretsift.yaml validate" $ok

# ---------------------------------------------------------------- other Pythons (optional)
if [ "${ALL_PYTHONS:-0}" = "1" ] && [ "${SKIP_INSTALL:-0}" != "1" ]; then
  for v in 3.11 3.12 3.13; do
    if command -v "python$v" >/dev/null 2>&1; then
      header "Python $v: fresh venv + unittest"
      "python$v" -m venv "$TMP/v$v" && "$TMP/v$v/bin/pip" install -q -e ".[dev]" \
        && PYTHONPATH="$ROOT/src" "$TMP/v$v/bin/python" -m unittest discover -s tests -t . -q
      pass_or_fail "Python $v: unittest suite" $?
    else
      skip "Python $v" "interpreter not found"
    fi
  done
else
  skip "other Python versions" "set ALL_PYTHONS=1 to run"
fi

# ---------------------------------------------------------------- audit (optional)
if [ "${AUDIT:-0}" = "1" ] && [ "${SKIP_INSTALL:-0}" != "1" ]; then
  header "pip-audit"
  "$PY" -m pip install -q pip-audit && "$PY" -m pip_audit
  pass_or_fail "pip-audit (installed environment)" $?
else
  skip "dependency audit" "set AUDIT=1 to run"
fi

# ---------------------------------------------------------------- summary
printf '\n==================== SUMMARY ====================\n'
fails=0
for r in "${RESULTS[@]}"; do
  echo "$r"
  case "$r" in FAIL*) fails=$((fails + 1)) ;; esac
done
echo "-------------------------------------------------"
if [ "$fails" -eq 0 ]; then echo "No FAIL lines."; else echo "$fails FAIL line(s): send the output of those blocks."; fi
echo "Note: ruff/mypy FAILs are style or typing findings, not runtime crashes."
exit $((fails > 0 ? 1 : 0))
