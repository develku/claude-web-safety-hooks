#!/bin/bash
# Unit tests for the cross-platform notification dispatcher (web-safety-notify.sh).
#
# The dispatcher replaces three hardcoded macOS `osascript` call sites with a
# single platform-aware sender. These tests pin the behaviour that matters for a
# SECURITY hook whose stdout is parsed as JSON by Claude Code:
#
#   - platform detection (macos / linux / wsl / windows / none), WSL before linux
#   - per-platform sanitization (Linux = argv + Pango-markup, NOT AppleScript):
#       * markup-escape order (& first, then < >) so no double-escaping
#       * C0+DEL control strip (\000-\037\177) — matches scanner.sh:164 precedent
#       * `--` end-of-options guard against option-injection (a `--help` title)
#   - headless gate: no DBUS session bus => notify-send is NOT invoked
#   - the hard invariant: a noisy notifier must NEVER leak onto the hook's stdout
#
# Platform is driven deterministically by stubbing `uname` (FAKE_UNAME_S) and by
# pointing the WSL probe at a temp file (WEB_SAFETY_PROC_VERSION) — thin seams so
# the matrix is testable on a real macOS dev box.

set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
NOTIFY_LIB="$REPO_ROOT/scripts/web-safety-notify.sh"

# --- PATH-stubbed binaries (so no real notification fires during the run) -----
FAKE_BIN=$(mktemp -d)
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$FAKE_BIN" "$TMP_ROOT"' EXIT

# Results are appended to a file (NOT shell vars): most cases run in subshells for
# env isolation, and subshell counter mutations are invisible to the parent.
RESULTS="$TMP_ROOT/results.tsv"; : >"$RESULTS"

# uname stub: echoes FAKE_UNAME_S regardless of flags (notify_platform calls `uname -s`).
cat >"$FAKE_BIN/uname" <<'EOF'
#!/bin/sh
echo "${FAKE_UNAME_S:-Linux}"
EOF

# notify-send stub: records each argv element on its own line to $NOTIFY_CAP,
# and optionally leaks $NOTIFY_LEAK to stdout to prove the dispatcher swallows it.
cat >"$FAKE_BIN/notify-send" <<'EOF'
#!/bin/sh
[ -n "${NOTIFY_LEAK:-}" ] && echo "$NOTIFY_LEAK"
if [ -n "${NOTIFY_CAP:-}" ]; then for a in "$@"; do printf '%s\n' "$a" >> "$NOTIFY_CAP"; done; fi
exit 0
EOF

# osascript stub: the macOS path feeds the script via heredoc (STDIN), so capture
# both args AND stdin to $OSA_CAP (proves the macOS path is preserved).
cat >"$FAKE_BIN/osascript" <<'EOF'
#!/bin/sh
if [ -n "${OSA_CAP:-}" ]; then printf '%s ' "$@" >> "$OSA_CAP"; cat >> "$OSA_CAP"; fi
exit 0
EOF

# sound players: record the event/file argument to $SND_CAP.
for p in canberra-gtk-play paplay pw-play; do
  cat >"$FAKE_BIN/$p" <<'EOF'
#!/bin/sh
if [ -n "${SND_CAP:-}" ]; then printf '%s\n' "$@" >> "$SND_CAP"; fi
exit 0
EOF
done

# powershell.exe stub: the Windows path passes title/subtitle/body via WST_* env
# vars (never interpolated into the -Command string). Record those env vars to
# $PS_CAP, and optionally leak $PS_LEAK to stdout to prove the dispatcher swallows
# it. (The real WinRT toast / XML escaping needs Windows and can't run here; these
# tests pin the bash-side contract: routing, env-var passing, control/CRLF strip,
# sound mapping, and stdout integrity.)
cat >"$FAKE_BIN/powershell.exe" <<'EOF'
#!/bin/sh
[ -n "${PS_LEAK:-}" ] && echo "$PS_LEAK"
if [ -n "${PS_CAP:-}" ]; then env | grep '^WST_' >> "$PS_CAP"; fi
exit 0
EOF

chmod +x "$FAKE_BIN"/*
export PATH="$FAKE_BIN:$PATH"

# Source the dispatcher under test (RED until web-safety-notify.sh exists).
# shellcheck source=/dev/null
. "$NOTIFY_LIB" 2>/dev/null || echo "  (note: $NOTIFY_LIB not sourced yet — expecting RED)"

pass() { printf 'P\t%s\n' "$1" >>"$RESULTS"; printf "  ✓ %s\n" "$1"; }
fail() { printf 'F\t%s\n' "$1" >>"$RESULTS"; printf "  ✗ %s\n" "$1"; }

# check_eq <name> <expected> <actual>
check_eq() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 — expected [$2] got [$3]"; fi
}

# require_dispatch — fail-fast guard so "nothing ran" cannot masquerade as a pass
# in the gate/invariant tests below. Returns non-zero (and records a failure) when
# the dispatcher function is not even defined.
have_dispatch() { declare -F notify_dispatch >/dev/null 2>&1; }

# A fresh proc-version file with the given contents; echoes its path.
mk_proc() { local f; f=$(mktemp "$TMP_ROOT/proc.XXXXXX"); printf '%s\n' "$1" >"$f"; echo "$f"; }

echo "Running web-safety notification dispatcher tests"
echo "  lib:  $NOTIFY_LIB"
echo ""

# =============================================================================
# 1. Platform detection
# =============================================================================
( export FAKE_UNAME_S=Darwin;  check_eq "detect: Darwin → macos"  "macos"   "$(notify_platform 2>/dev/null)" )
( export FAKE_UNAME_S=Linux WEB_SAFETY_PROC_VERSION="$(mk_proc 'Linux version 6.1.0-generic')"
  check_eq "detect: Linux → linux" "linux" "$(notify_platform 2>/dev/null)" )
( export FAKE_UNAME_S=Linux WEB_SAFETY_PROC_VERSION="$(mk_proc 'Linux version 5.15.0-microsoft-standard-WSL2')"
  check_eq "detect: Linux+microsoft → wsl (before linux)" "wsl" "$(notify_platform 2>/dev/null)" )
( export FAKE_UNAME_S=MINGW64_NT-10.0; check_eq "detect: MINGW* → windows" "windows" "$(notify_platform 2>/dev/null)" )
( export FAKE_UNAME_S=Plan9;          check_eq "detect: unknown OS → none"  "none"    "$(notify_platform 2>/dev/null)" )

# =============================================================================
# 2. Linux sanitization — markup escaping (Pango/XML on gtk_label_set_markup daemons)
#    Order matters: & MUST be escaped first, or < becomes &amp;lt; (double-escape).
# =============================================================================
check_eq "escape: bare & → &amp; (not &amp;amp;)" "&amp;"              "$(_notify_escape_body '&' 2>/dev/null)"
check_eq "escape: a<b>c → entities"               "a&lt;b&gt;c"        "$(_notify_escape_body 'a<b>c' 2>/dev/null)"
check_eq "escape: <&> ordering (no double)"       "&lt;&amp;&gt;"      "$(_notify_escape_body '<&>' 2>/dev/null)"

# =============================================================================
# 3. Linux sanitization — control-char strip. The verify pass caught a regex that
#    wrongly PRESERVED TAB/LF/CR; the fix matches scanner.sh:164 (\000-\037\177:
#    strip ALL C0 + DEL). 0x01, TAB, LF, CR must all be removed.
# =============================================================================
check_eq "strip: C0/DEL/TAB/LF/CR all removed" "abcde" \
  "$(_notify_escape_body "$(printf 'a\001b\tc\nd\re')" 2>/dev/null)"

# =============================================================================
# 4. Linux send — option-injection guard. A title of `--help` must reach
#    notify-send as a positional, guarded by a literal `--` end-of-options token.
# =============================================================================
(
  export FAKE_UNAME_S=Linux WEB_SAFETY_PROC_VERSION="$(mk_proc 'Linux 6.1')"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
  export NOTIFY_CAP="$TMP_ROOT/optinj.cap"; : >"$NOTIFY_CAP"
  notify_dispatch MEDIUM "--help" "body text" "" >/dev/null 2>&1
  if grep -qx -- "--" "$NOTIFY_CAP" 2>/dev/null; then
    pass "linux: '--' end-of-options guard present before positionals"
  else
    fail "linux: '--' option-injection guard missing in notify-send argv"
  fi
)

# =============================================================================
# 5. Linux send — severity → urgency mapping (HIGH = critical, sticky).
# =============================================================================
(
  export FAKE_UNAME_S=Linux WEB_SAFETY_PROC_VERSION="$(mk_proc 'Linux 6.1')"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
  export NOTIFY_CAP="$TMP_ROOT/urg.cap"; : >"$NOTIFY_CAP"
  notify_dispatch HIGH "Title" "body" "" >/dev/null 2>&1
  if grep -qx -- "--urgency=critical" "$NOTIFY_CAP" 2>/dev/null; then
    pass "linux: HIGH → --urgency=critical"
  else
    fail "linux: HIGH did not map to --urgency=critical"
  fi
)

# =============================================================================
# 6. Linux headless gate — no DBUS session bus ⇒ notify-send NOT invoked
#    (SSH/cron/headless must not error and must not block).
# =============================================================================
(
  export FAKE_UNAME_S=Linux WEB_SAFETY_PROC_VERSION="$(mk_proc 'Linux 6.1')"
  unset DBUS_SESSION_BUS_ADDRESS
  export NOTIFY_CAP="$TMP_ROOT/headless.cap"; : >"$NOTIFY_CAP"
  if ! have_dispatch; then
    fail "linux: headless gate — notify_dispatch not defined (cannot test gate)"
  else
    notify_dispatch HIGH "Title" "body" "" >/dev/null 2>&1
    if [ -s "$NOTIFY_CAP" ]; then
      fail "linux: notify-send was invoked despite no DBUS session bus"
    else
      pass "linux: headless (no DBUS) skips notify-send cleanly"
    fi
  fi
)

# =============================================================================
# 7. THE HARD INVARIANT — a noisy notifier must NOT corrupt the hook's JSON stdout.
#    notify-send leaks "GARBAGE"; the dispatcher must emit zero bytes on stdout.
# =============================================================================
(
  export FAKE_UNAME_S=Linux WEB_SAFETY_PROC_VERSION="$(mk_proc 'Linux 6.1')"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
  export NOTIFY_LEAK="GARBAGE_ON_STDOUT"
  export NOTIFY_CAP="$TMP_ROOT/leak.cap"; : >"$NOTIFY_CAP"
  out=$(notify_dispatch HIGH "Title" "body" "" 2>/dev/null)
  # Discriminating: the notifier must have RUN (cap non-empty) AND nothing leaked.
  if [ ! -s "$NOTIFY_CAP" ]; then
    fail "stdout: dispatcher never reached notify-send (cannot test leak invariant)"
  elif [ -z "$out" ]; then
    pass "stdout: dispatcher emits nothing even when notifier is noisy"
  else
    fail "stdout: notifier output leaked onto hook stdout: [$out]"
  fi
)

# =============================================================================
# 8. Linux best-effort sound — HIGH selects the dialog-error event via canberra.
# =============================================================================
(
  export FAKE_UNAME_S=Linux WEB_SAFETY_PROC_VERSION="$(mk_proc 'Linux 6.1')"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
  export SND_CAP="$TMP_ROOT/snd.cap"; : >"$SND_CAP"
  notify_dispatch HIGH "Title" "body" "" >/dev/null 2>&1
  # the sound player runs backgrounded; give it a beat to write
  sleep 0.3
  if grep -q "dialog-error" "$SND_CAP" 2>/dev/null; then
    pass "linux: HIGH plays dialog-error sound (best-effort)"
  else
    fail "linux: HIGH sound event (dialog-error) not played"
  fi
)

# =============================================================================
# 9. macOS path preserved — refactor must keep firing osascript on Darwin.
# =============================================================================
(
  export FAKE_UNAME_S=Darwin
  export OSA_CAP="$TMP_ROOT/osa.cap"; : >"$OSA_CAP"
  notify_dispatch HIGH "MacTitle" "mac body message" "" >/dev/null 2>&1
  if grep -q "mac body message" "$OSA_CAP" 2>/dev/null; then
    pass "macos: osascript still invoked with the message (refactor preserved)"
  else
    fail "macos: osascript path lost in refactor"
  fi
)

# grep -c prints 0 (exit 1) when there are no matches; the file always exists, so
# read the count directly — a `|| echo 0` would append a SECOND 0 and break $(()).
# =============================================================================
# 10. Windows toast path (PR #2). The real WinRT toast needs Windows; here we
#     pin the bash-side contract that the Windows code must satisfy.
# =============================================================================

# 10a. Native Git-Bash (MINGW*) routes to powershell.exe.
(
  export FAKE_UNAME_S=MINGW64_NT-10.0
  export PS_CAP="$TMP_ROOT/ps-route.cap"; : >"$PS_CAP"
  notify_dispatch HIGH "WinTitle" "win body" "win sub" >/dev/null 2>&1
  if [ -s "$PS_CAP" ]; then
    pass "windows: MINGW routes to powershell.exe with WST_* env"
  else
    fail "windows: powershell.exe not invoked on MINGW (no WST_* env captured)"
  fi
)

# 10b. Title/body are passed via env vars (not interpolated into -Command).
(
  export FAKE_UNAME_S=MINGW64_NT-10.0
  export PS_CAP="$TMP_ROOT/ps-env.cap"; : >"$PS_CAP"
  notify_dispatch MEDIUM "MyTitle" "MyBody" "" >/dev/null 2>&1
  if grep -qx "WST_TITLE=MyTitle" "$PS_CAP" 2>/dev/null && grep -qx "WST_BODY=MyBody" "$PS_CAP" 2>/dev/null; then
    pass "windows: title/body passed via WST_* env vars"
  else
    fail "windows: WST_TITLE/WST_BODY env contract not met"
  fi
)

# 10c. Bash-side defense-in-depth strips C0/DEL AND CR/LF (toast UI-spoof guard)
#      before the value crosses to PowerShell. 0x01 + CRLF must be gone.
(
  export FAKE_UNAME_S=MINGW64_NT-10.0
  export PS_CAP="$TMP_ROOT/ps-strip.cap"; : >"$PS_CAP"
  notify_dispatch LOW "$(printf 'Ti\001tle\r\nX')" "body" "" >/dev/null 2>&1
  if grep -qx "WST_TITLE=TitleX" "$PS_CAP" 2>/dev/null; then
    pass "windows: bash strips C0/DEL + CR/LF before PowerShell"
  else
    fail "windows: control/CRLF not stripped on the bash side ($(grep '^WST_TITLE=' "$PS_CAP" 2>/dev/null))"
  fi
)

# 10d. Severity → ms-winsoundevent mapping (HIGH = Notification.Reminder).
(
  export FAKE_UNAME_S=MINGW64_NT-10.0
  export PS_CAP="$TMP_ROOT/ps-snd.cap"; : >"$PS_CAP"
  notify_dispatch HIGH "T" "b" "" >/dev/null 2>&1
  if grep -qx "WST_SOUND=Notification.Reminder" "$PS_CAP" 2>/dev/null; then
    pass "windows: HIGH → ms-winsoundevent Notification.Reminder"
  else
    fail "windows: HIGH sound not mapped to Notification.Reminder"
  fi
)

# 10e. Stdout integrity — a noisy powershell.exe must not leak onto JSON stdout.
(
  export FAKE_UNAME_S=MINGW64_NT-10.0
  export PS_LEAK="WIN_GARBAGE"
  export PS_CAP="$TMP_ROOT/ps-leak.cap"; : >"$PS_CAP"
  out=$(notify_dispatch HIGH "T" "b" "" 2>/dev/null)
  if [ ! -s "$PS_CAP" ]; then
    fail "windows: dispatcher never reached powershell.exe (cannot test leak)"
  elif [ -z "$out" ]; then
    pass "windows: dispatcher emits nothing even when powershell is noisy"
  else
    fail "windows: powershell output leaked onto hook stdout: [$out]"
  fi
)

# 10f. Fail-safe — MINGW but NO powershell.exe on PATH ⇒ clean no-op (no crash,
#      no stdout). Uses a minimal PATH containing only a uname stub.
(
  NOPS="$TMP_ROOT/nops"; mkdir -p "$NOPS"
  printf '#!/bin/sh\necho MINGW64_NT-10.0\n' > "$NOPS/uname"; chmod +x "$NOPS/uname"
  if ! have_dispatch; then
    fail "windows: fail-safe — notify_dispatch not defined"
  else
    out=$(PATH="$NOPS" notify_dispatch HIGH "T" "b" "" 2>/dev/null); rc=$?
    if [ "$rc" -eq 0 ] && [ -z "$out" ]; then
      pass "windows: no powershell.exe → clean no-op (no crash, no stdout)"
    else
      fail "windows: missing powershell.exe not handled fail-safe (rc=$rc out=[$out])"
    fi
  fi
)

PASS=$(grep -c '^P' "$RESULTS"); PASS=${PASS:-0}
FAIL=$(grep -c '^F' "$RESULTS"); FAIL=${FAIL:-0}

echo ""
echo "Results: $PASS passed, $FAIL failed (total $((PASS + FAIL)))"
if [ "$FAIL" -ne 0 ]; then
  echo ""
  echo "Failures:"
  grep '^F' "$RESULTS" | cut -f2- | while IFS= read -r f; do echo "  - $f"; done
  exit 1
fi
exit 0
