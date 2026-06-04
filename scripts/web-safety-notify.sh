#!/bin/bash
# web-safety-notify.sh — cross-platform desktop-notification dispatcher for the
# web-safety hooks. Sourced, never executed; defines functions only, with no
# side effects at source time (same contract as web-safety-lib.sh).
#
# Replaces three hardcoded macOS `osascript` call sites (scanner send_notification,
# egress emit_ask, approve block_url) with ONE platform-aware sender.
#
# Hard invariants for a Claude Code hook whose stdout is parsed as JSON:
#   - best-effort: a missing notifier, headless session, or notifier crash is
#     ALWAYS a silent no-op — it must never block the hook.
#   - NO path may write to stdout. Every notifier invocation is redirected
#     (>/dev/null 2>&1); notify_dispatch itself returns 0 unconditionally.
#
# The injection model differs per platform, so sanitization lives in the per-OS
# senders, NOT at the call sites:
#   - macOS osascript re-evaluates a string literal  → strip " and \
#   - Linux notify-send takes argv (no shell re-eval) → `--` option guard +
#     Pango/XML markup-escape (& first) + C0/DEL control strip
#   - Windows toast is XML markup                      → strip XML-illegal chars
#     + SecurityElement::Escape inside PowerShell (authoritative)

# notify_platform — echo one of: macos | linux | wsl | windows | none
# WSL is checked BEFORE generic linux (its `uname -s` is also "Linux").
# The proc-version path is overridable (WEB_SAFETY_PROC_VERSION) purely as a
# test seam; it defaults to the real /proc/version.
notify_platform() {
  case "$(uname -s 2>/dev/null)" in
    Darwin) echo macos ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    Linux)
      if grep -qiE 'microsoft|wsl' "${WEB_SAFETY_PROC_VERSION:-/proc/version}" 2>/dev/null; then
        echo wsl
      else
        echo linux
      fi ;;
    *) echo none ;;
  esac
}

# _notify_strip_ctl <text> — remove C0 control chars + DEL (\000-\037\177),
# which also removes CR/LF (single-line guard against toast/log spoofing).
# Matches the scanner.sh:164 scrub. LC_ALL=C makes tr byte-wise so arbitrary
# attacker bytes can't trip an "illegal byte sequence" error under a UTF-8
# locale. Shared by the Linux and Windows senders; the macOS quote/backslash
# strip is a separate, OS-specific model.
_notify_strip_ctl() {
  printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177'
}

# _notify_escape_body <text> — Linux notify-send sanitizer: control-strip, then
# Pango/XML markup-escape. notify-send takes argv (no shell re-eval), so the two
# real risks are option-injection (guarded by `--` at the call site) and markup:
# daemons rendering the body via gtk_label_set_markup() (e.g. XFCE) treat & < >
# as markup and silently drop a body with a raw &. Escape & FIRST, else `<`
# becomes `&amp;lt;` (double-escape).
_notify_escape_body() {
  _notify_strip_ctl "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

# Severity → platform-specific alert style.
_notify_sevmap_macos() {
  case "$1" in
    HIGH) echo "Basso" ;; MEDIUM) echo "Sosumi" ;; LOW) echo "Ping" ;; *) echo "Sosumi" ;;
  esac
}
# echoes "<urgency> <xdg-sound-event>"
_notify_sevmap_linux() {
  case "$1" in
    HIGH)   echo "critical dialog-error" ;;
    MEDIUM) echo "normal dialog-warning" ;;
    LOW)    echo "low message-new-instant" ;;
    *)      echo "normal dialog-warning" ;;
  esac
}

# _notify_macos <severity> <title> <message> <subtitle> <sound>
# Preserves the exact prior osascript behaviour (heredoc, " / \ strip, sync,
# fully redirected). An explicit <sound> overrides the severity default so the
# PreToolUse call sites keep their distinctive Funk / Sosumi cues.
_notify_macos() {
  local severity="$1" title="$2" message="$3" subtitle="$4" sound="$5"
  [ -n "$sound" ] || sound=$(_notify_sevmap_macos "$severity")
  command -v osascript >/dev/null 2>&1 || return 0
  local safe_title="${title//[\"\\]/ }"
  local safe_message="${message//[\"\\]/ }"
  local safe_subtitle="${subtitle//[\"\\]/ }"
  if [ -n "$safe_subtitle" ]; then
    osascript <<EOF >/dev/null 2>&1
display notification "${safe_message}" with title "${safe_title}" subtitle "${safe_subtitle}" sound name "${sound}"
EOF
  else
    osascript <<EOF >/dev/null 2>&1
display notification "${safe_message}" with title "${safe_title}" sound name "${sound}"
EOF
  fi
}

# _notify_linux <severity> <title> <message> <subtitle>
# libnotify has no "subtitle" — fold it into the body. Gate on BOTH the binary
# AND a session bus (headless/SSH/cron has notify-send but no DBUS → it would
# fail). Sound is a SEPARATE best-effort process (notify-send has none).
_notify_linux() {
  local severity="$1" title="$2" message="$3" subtitle="$4"
  [ -n "$subtitle" ] && message="${message}"$'\n'"${subtitle}"
  command -v notify-send >/dev/null 2>&1 || return 0
  [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || return 0

  local map urgency snd_event
  map=$(_notify_sevmap_linux "$severity"); urgency="${map%% *}"; snd_event="${map##* }"

  local safe_title safe_message
  safe_title=$(_notify_escape_body "$title")
  safe_message=$(_notify_escape_body "$message")

  # `--` ends option parsing so a title/body starting with '-' can't be a flag.
  notify-send --app-name="web-safety" --urgency="$urgency" --icon=dialog-warning \
    -- "$safe_title" "$safe_message" >/dev/null 2>&1 || true

  # Best-effort sound, backgrounded so it never blocks; absent player = silent.
  if command -v canberra-gtk-play >/dev/null 2>&1; then
    canberra-gtk-play -i "$snd_event" >/dev/null 2>&1 &
  elif command -v paplay >/dev/null 2>&1; then
    paplay "/usr/share/sounds/freedesktop/stereo/${snd_event}.oga" >/dev/null 2>&1 &
  elif command -v pw-play >/dev/null 2>&1; then
    pw-play "/usr/share/sounds/freedesktop/stereo/${snd_event}.oga" >/dev/null 2>&1 &
  fi
}

# _notify_windows <severity> <title> <message> <subtitle>
# Native Windows toast via Windows PowerShell + WinRT. Title/subtitle/body are
# passed as ENV VARS (WST_*), NEVER interpolated into the -Command string, so an
# attacker string cannot break out of the script or the toast XML.
#
# PowerShell is the AUTHORITATIVE sanitizer (the only layer guaranteed to run):
# X() keeps only printable chars (code point >= 32, excluding DEL 127, the lone
# surrogate range 55296-57343, and non-chars 65534/65535) — dropping every
# XML-1.0-illegal char (incl. CR/LF, so the toast stays single-line) BEFORE
# LoadXml. Otherwise a raw control char makes LoadXml throw and the toast never
# fires (attacker-controlled alert suppression). It THEN XML-escapes via
# SecurityElement::Escape. The bash side also strips C0/DEL+CRLF as
# defense-in-depth. $sound and $AppId are trusted constants, never derived from
# tool output. try/catch keeps a throw or a missing AUMID from aborting the hook;
# output is fully redirected so the hook's JSON stdout is never corrupted.
_notify_windows() {
  local severity="$1" title="$2" message="$3" subtitle="$4"
  command -v powershell.exe >/dev/null 2>&1 || return 0

  local snd
  case "$severity" in
    HIGH)   snd="Notification.Reminder" ;;
    MEDIUM) snd="Notification.SMS" ;;
    LOW)    snd="Notification.Default" ;;
    *)      snd="Notification.SMS" ;;
  esac

  WST_TITLE="$(_notify_strip_ctl "$title"  | cut -c1-200)" \
  WST_SUB="$(_notify_strip_ctl "$subtitle" | cut -c1-200)" \
  WST_BODY="$(_notify_strip_ctl "$message" | cut -c1-400)" \
  WST_SOUND="$snd" \
  powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command '
$ErrorActionPreference = "Stop"
try {
  function X($s) {
    if ($null -eq $s) { return "" }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
      $c = [int]$ch
      if ($c -ge 32 -and $c -ne 127 -and ($c -lt 55296 -or $c -gt 57343) -and $c -ne 65534 -and $c -ne 65535) {
        [void]$sb.Append($ch)
      }
    }
    return [System.Security.SecurityElement]::Escape($sb.ToString())
  }
  $t = X $env:WST_TITLE; $sub = X $env:WST_SUB; $b = X $env:WST_BODY
  $snd = $env:WST_SOUND
  $audio = "<audio src=`"ms-winsoundevent:$snd`"/>"
  $subLine = if ([string]::IsNullOrEmpty($sub)) { "" } else { "<text>$sub</text>" }
  $xml = "<toast><visual><binding template=`"ToastGeneric`"><text>$t</text>$subLine<text>$b</text></binding></visual>$audio</toast>"
  $AppId = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
  $doc = [Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]::New()
  $doc.LoadXml($xml)
  [Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]::CreateToastNotifier($AppId).Show($doc)
} catch { }
' >/dev/null 2>&1 || true
}

# notify_dispatch <severity> <title> <message> [subtitle] [macos_sound]
# severity ∈ {HIGH,MEDIUM,LOW}. Routes to the per-OS sender. ALWAYS returns 0 and
# NEVER writes to stdout.
notify_dispatch() {
  local severity="${1:-MEDIUM}" title="${2:-}" message="${3:-}" subtitle="${4:-}" sound="${5:-}"
  case "$(notify_platform)" in
    macos)   _notify_macos "$severity" "$title" "$message" "$subtitle" "$sound" ;;
    linux)   _notify_linux "$severity" "$title" "$message" "$subtitle" ;;
    wsl)
      # Prefer the in-distro daemon when a display is reachable (WSLg), else the
      # Windows toast path via powershell.exe interop.
      if command -v notify-send >/dev/null 2>&1 && { [ -n "${WAYLAND_DISPLAY:-}" ] || [ -n "${DISPLAY:-}" ]; }; then
        _notify_linux "$severity" "$title" "$message" "$subtitle"
      else
        _notify_windows "$severity" "$title" "$message" "$subtitle"
      fi ;;
    windows) _notify_windows "$severity" "$title" "$message" "$subtitle" ;;
    *)       : ;;
  esac
  return 0
}
