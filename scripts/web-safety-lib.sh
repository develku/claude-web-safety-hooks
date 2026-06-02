#!/bin/bash
# web-safety-lib.sh — shared host-normalization + classification helpers for the
# PreToolUse hooks (web-safety-approve.sh URL pre-screen, web-safety-egress.sh
# destination allowlist). Sourced, never executed; defines functions only, no
# side effects at source time.
#
# Single source of truth so the two hooks cannot drift on how a host is parsed
# or which hosts count as internal.
#
# The normalizer aims to produce the host a WHATWG/curl-style client would
# actually connect to, so the SSRF classifier checks the SAME host the fetch
# uses (parser-disagreement is the classic SSRF bypass). It is deliberately
# fail-toward-block: ambiguous/hostile authorities resolve to the sentinel
# "ws-invalid-authority", which host_is_internal treats as internal.

# _percent_decode <s> — decode %XX sequences (perl; reads stdin, no shell eval).
_percent_decode() {
  printf '%s' "$1" | perl -pe 's/%([0-9a-fA-F]{2})/chr(hex($1))/ge' 2>/dev/null
}

# _ipv4_canonical <host> — collapse an integer-encoded IPv4 (whole decimal,
# octal 0NNN, or hex 0x…, and dotted forms whose labels are any of those) to
# canonical dotted-quad decimal, inet_aton-style. Non-IP hosts pass through.
# perl is a hard dependency (see .github/workflows/tests.yml).
_ipv4_canonical() {
  printf '%s' "$1" | perl -ne '
    chomp(my $h = $_);
    # whole integer: hex (0x..), octal (leading 0), or decimal
    if ($h =~ /^(0x[0-9a-f]+|0[0-7]*|[1-9][0-9]*)$/) {
      my $n = ($h =~ /^0/) ? oct($h) : $h + 0;   # oct() parses 0x.. and 0NNN(octal)
      if (defined $n && $n >= 0 && $n <= 4294967295) {
        printf "%d.%d.%d.%d", ($n>>24)&255, ($n>>16)&255, ($n>>8)&255, $n&255;
        exit;
      }
      print $h; exit;
    }
    # dotted form whose labels may be octal/hex/decimal (e.g. 0177.0.0.1)
    if ($h =~ /\./ && $h =~ /^[0-9a-fx]+(\.[0-9a-fx]+)+$/) {
      my @p = split /\./, $h, -1;
      if (@p >= 2 && @p <= 4 && !grep { !/^(0x[0-9a-f]+|[0-9]+)$/ } @p) {
        my @o = map { /^0x/ ? hex($_) : (/^0[0-7]+$/ ? oct($_) : $_ + 0) } @p;
        print join(".", @o); exit;
      }
    }
    print $h;
  ' 2>/dev/null
}

# normalize_host <url-or-host> — echo the canonical lowercased bare host, or the
# literal "ws-invalid-authority" when the authority is hostile/ambiguous.
normalize_host() {
  local raw="$1" host _prev _i
  # Embedded control chars (CR/LF/tab) → request-splitting / desync. Block.
  case "$raw" in *[$'\r\n\t']*) printf 'ws-invalid-authority'; return ;; esac
  host="${raw#*://}"      # strip scheme (no-op if absent)
  host="${host//\\//}"    # WHATWG: backslash is equivalent to slash in the authority
  host="${host%%/*}"      # strip path  (after \→/ so a path-confusion '\' can't hide the host)
  host="${host%%\?*}"     # strip query
  host="${host%%#*}"      # strip fragment
  host="${host##*@}"      # strip userinfo  user[:pass]@  (greedy: last @)
  case "$host" in
    \[*\]*) : ;;          # bracketed IPv6 literal — keep brackets/colons
    *:*) host="${host%%:*}" ;;   # strip :port
  esac
  # Percent-decode to a FIXED POINT (≤3 passes): a double/triple-encoded host
  # (e.g. %2531%2532%2537 → %31%32%37 → 127) would otherwise be classified
  # against the still-encoded string while a multi-decoding fetcher reaches the
  # internal target. A separator/control re-introduced by decoding, OR any
  # residual %XX after the loop, is hostile (legit hosts never contain '%') →
  # sentinel, which host_is_internal blocks.
  _prev=""; _i=0
  while [ "$host" != "$_prev" ] && [ "$_i" -lt 3 ]; do
    _prev="$host"; host=$(_percent_decode "$host"); _i=$((_i + 1))
  done
  case "$host" in
    *[/@\\]* | *[$'\r\n\t']* | *%[0-9a-fA-F][0-9a-fA-F]*) printf 'ws-invalid-authority'; return ;;
  esac
  host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')
  _ipv4_canonical "$host"
}

# host_is_internal <host> — true (0) if the (normalized) host is a loopback /
# private / link-local / cloud-metadata target that must never be fetched.
# allowlist cannot override this.
#
# CONSUMER CONTRACT: for IP-literal hosts, pair this with host_is_bare_ip (as
# web-safety-approve.sh does — it blocks on either). host_is_internal classifies
# hex-grouped IPv4-mapped IPv6 only for loopback (::ffff:7f..) and AWS metadata
# (::ffff:a9fe); a hex-grouped PRIVATE range (e.g. [::ffff:0a00:0001] = 10.0.0.1)
# is caught by host_is_bare_ip, not here. Any future consumer (e.g. the egress
# guard) MUST call both, or first canonicalize the embedded IPv4.
host_is_internal() {
  local h="$1" inner
  # Parser-desync sentinel → block.
  [ "$h" = "ws-invalid-authority" ] && return 0
  # IPv4-mapped / IPv4-compatible IPv6 (e.g. [::ffff:127.0.0.1], [::169.254.169.254])
  # → reclassify the embedded dotted IPv4.
  case "$h" in
    \[*:*.*.*.*\] | *:*.*.*.*)
      inner="${h#\[}"; inner="${inner%\]}"; inner="${inner##*:}"
      case "$inner" in
        *.*.*.*) host_is_internal "$(_ipv4_canonical "$inner")" && return 0 ;;
      esac ;;
  esac
  # Hex-grouped IPv4-mapped loopback (7f00:…) / AWS metadata (a9fe:a9fe).
  case "$h" in
    *:ffff:7f[0-9a-f][0-9a-f]:* | \[*:ffff:7f* | *:ffff:a9fe* | \[*:ffff:a9fe*) return 0 ;;
  esac
  case "$h" in
    localhost|*.localhost) return 0 ;;
    metadata|metadata.*|*.internal) return 0 ;;   # GCP metadata.google.internal, *.internal
  esac
  # IPv4 ranges (h is canonical dotted if it arrived as an integer form)
  case "$h" in
    0.*|127.*|10.*|192.168.*|169.254.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
  esac
  # IPv6 loopback / unique-local / link-local (bracketed or bare)
  case "$h" in
    ::1|\[::1\]|fc??:*|fd??:*|\[fc*|\[fd*|fe80:*|\[fe80:*) return 0 ;;
  esac
  return 1
}

# host_is_bare_ip <host> — true (0) if <host> is a bare IPv4 dotted-quad or an
# IPv6 literal (no domain name). Mirrors the old "direct IP address" hard block;
# legitimate web content uses domains, not raw IPs.
host_is_bare_ip() {
  local h="$1"
  case "$h" in
    \[*:*\]|*:*:*) return 0 ;;   # IPv6 literal
  esac
  printf '%s' "$h" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

# host_in_list <host> <listfile> — true (0) if <host> equals or is a subdomain
# of any entry in <listfile>. Comment-aware (# lines), blank-line safe, and
# tolerant of a final line with no trailing newline.
host_in_list() {
  local host="$1" listfile="$2" domain
  [ -f "$listfile" ] || return 1
  while IFS= read -r domain || [ -n "$domain" ]; do
    case "$domain" in ''|\#*) continue ;; esac
    domain=$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    [ -z "$domain" ] && continue
    case "$host" in "$domain"|*."$domain") return 0 ;; esac
  done < "$listfile"
  return 1
}
