#!/usr/bin/env bash
# assertions.sh — TAP-compatible test assertion helpers
# Source this file from lifecycle-suite.sh
set -euo pipefail

# Global test counter
_TEST_NUM=0
_TEST_FAILURES=0

tap_plan() {
  echo "1..$1"
}

_tap_ok() {
  _TEST_NUM=$((_TEST_NUM + 1))
  echo "ok $_TEST_NUM - $1"
}

_tap_not_ok() {
  _TEST_NUM=$((_TEST_NUM + 1))
  _TEST_FAILURES=$((_TEST_FAILURES + 1))
  echo "not ok $_TEST_NUM - $1"
  if [[ -n "${2:-}" ]]; then
    echo "  ---"
    echo "  message: $2"
    echo "  ..."
  fi
}

tap_summary() {
  echo "# Tests: $_TEST_NUM"
  echo "# Failures: $_TEST_FAILURES"
  if [[ $_TEST_FAILURES -gt 0 ]]; then
    echo "# FAIL"
    return 1
  else
    echo "# PASS"
    return 0
  fi
}

# --- Assertion functions ---

# assert_exit_code <expected> <description> <command...>
# Runs command, checks exit code matches expected
assert_exit_code() {
  local expected="$1"; shift
  local desc="$1"; shift
  local actual=0
  "$@" >/dev/null 2>&1 || actual=$?
  if [[ "$actual" -eq "$expected" ]]; then
    _tap_ok "$desc"
  else
    _tap_not_ok "$desc" "expected exit code $expected, got $actual"
  fi
}

# assert_success <description> <command...>
assert_success() {
  local desc="$1"; shift
  local output
  local rc=0
  output=$("$@" 2>&1) || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    _tap_ok "$desc"
  else
    _tap_not_ok "$desc" "command failed with exit code $rc: $output"
  fi
}

# assert_failure <description> <command...>
assert_failure() {
  local desc="$1"; shift
  local output
  local rc=0
  output=$("$@" 2>&1) || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    _tap_ok "$desc"
  else
    _tap_not_ok "$desc" "expected failure but command succeeded"
  fi
}

# assert_output_contains <description> <needle> <command...>
assert_output_contains() {
  local desc="$1"; shift
  local needle="$1"; shift
  local output
  output=$("$@" 2>&1) || true
  if echo "$output" | grep -qF "$needle"; then
    _tap_ok "$desc"
  else
    _tap_not_ok "$desc" "output does not contain '$needle'"
  fi
}

# assert_output_not_contains <description> <needle> <command...>
assert_output_not_contains() {
  local desc="$1"; shift
  local needle="$1"; shift
  local output
  output=$("$@" 2>&1) || true
  if echo "$output" | grep -qF "$needle"; then
    _tap_not_ok "$desc" "output contains '$needle' (should not)"
  else
    _tap_ok "$desc"
  fi
}

# assert_output_matches <description> <regex> <command...>
assert_output_matches() {
  local desc="$1"; shift
  local regex="$1"; shift
  local output
  output=$("$@" 2>&1) || true
  if echo "$output" | grep -qE "$regex"; then
    _tap_ok "$desc"
  else
    _tap_not_ok "$desc" "output does not match regex '$regex'"
  fi
}

# assert_file_exists <description> <path>
assert_file_exists() {
  local desc="$1"
  local filepath="$2"
  if [[ -f "$filepath" ]]; then
    _tap_ok "$desc"
  else
    _tap_not_ok "$desc" "file does not exist: $filepath"
  fi
}

# assert_file_not_exists <description> <path>
assert_file_not_exists() {
  local desc="$1"
  local filepath="$2"
  if [[ ! -f "$filepath" ]]; then
    _tap_ok "$desc"
  else
    _tap_not_ok "$desc" "file exists but should not: $filepath"
  fi
}

# assert_json_field <description> <field> <expected_value> <json_string>
assert_json_field() {
  local desc="$1"
  local field="$2"
  local expected="$3"
  local json="$4"
  local actual
  actual=$(echo "$json" | node -e "
    let d='';process.stdin.on('data',c=>d+=c);
    process.stdin.on('end',()=>{try{console.log(JSON.parse(d)$(echo "$field"))}catch(e){console.log('PARSE_ERROR')}})
  " 2>/dev/null) || actual="PARSE_ERROR"
  if [[ "$actual" == "$expected" ]]; then
    _tap_ok "$desc"
  else
    _tap_not_ok "$desc" "expected $field=$expected, got $actual"
  fi
}

# run_capturing <command...>
# Captures stdout+stderr into $CAPTURED_OUTPUT, exit code into $CAPTURED_RC
CAPTURED_OUTPUT=""
CAPTURED_RC=0
run_capturing() {
  CAPTURED_OUTPUT=""
  CAPTURED_RC=0
  CAPTURED_OUTPUT=$("$@" 2>&1) || CAPTURED_RC=$?
}
