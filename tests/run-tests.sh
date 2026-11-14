#!/usr/bin/env bash
# Tests for the hardening checkers. Linux: real read-only run + SSH config
# fixtures. Windows script: syntax + helper functions (no Windows APIs on Linux).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail() { echo "FAIL: $*"; exit 1; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

echo "== bash: insecure sshd_config is flagged"
./check-linux.sh -n -c tests/fixtures/sshd_config.insecure > "$W/bad.txt"; rc=$?
[[ $rc -eq 2 ]] || fail "expected exit 2 with FAILs, got $rc"
for pat in "FAIL.*PermitRootLogin yes" "FAIL.*PermitEmptyPasswords yes" "FAIL.*Protocol 2,1" "WARN.*MaxAuthTries 10"; do
    grep -Eq "$pat" "$W/bad.txt" || fail "missing: $pat"
done

echo "== bash: hardened sshd_config passes SSH checks (Match block ignored)"
./check-linux.sh -n -c tests/fixtures/sshd_config.hardened -o "$W/report.txt" > "$W/good.txt"
grep -A8 '== SSH server ==' "$W/good.txt" | grep -Eq 'FAIL|WARN' && fail "hardened SSH config should not WARN/FAIL"
grep -q "PasswordAuthentication no" "$W/good.txt" || fail "Match block leaked into global settings"
grep -q "^Summary:" "$W/report.txt" || fail "report file missing summary"

echo "== bash: usage errors"
./check-linux.sh -x >/dev/null 2>&1; [[ $? -eq 3 ]] || fail "bad option should exit 3"
grep -q Usage <<< "$(./check-linux.sh -h)" || fail "help missing"

echo "== bash: script never writes outside its report (read-only)"
grep -Eq '(^|[^>])>[^&>/]*/etc/|chmod|chown|systemctl (start|stop|enable|disable)|sed -i|ufw (enable|allow|deny)' check-linux.sh && fail "found a state-changing command"

if command -v pwsh >/dev/null 2>&1; then
    echo "== pwsh: helper functions and non-Windows guard"
    # shellcheck disable=SC2016  # PowerShell code, expanded by pwsh
    pwsh -NoProfile -Command '
        $ErrorActionPreference = "Stop"
        $env:HARDENING_CHECKER_TEST = "1"
        . ./check-windows.ps1
        $na = ConvertFrom-NetAccount (Get-Content tests/fixtures/net-accounts.txt)
        if ($na["Minimum password length"] -ne "8") { throw "net accounts parse: length" }
        if ($na["Lockout threshold"] -ne "Never") { throw "net accounts parse: lockout" }
        $items = @([pscustomobject]@{Level="PASS"}, [pscustomobject]@{Level="WARN"}, [pscustomobject]@{Level="FAIL"}, [pscustomobject]@{Level="INFO"})
        if ((Get-Score $items) -ne 50) { throw "score should be 50" }
        "helpers OK"
    ' || fail "pwsh helper tests"
    env -u HARDENING_CHECKER_TEST pwsh -NoProfile -File ./check-windows.ps1 >/dev/null 2>&1; rc=$?
    [[ $rc -eq 3 ]] || fail "non-Windows guard should exit 3, got $rc"
fi
echo "All tests passed."
