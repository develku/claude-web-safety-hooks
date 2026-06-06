---
description: Add a content-trusted domain — downgrade the content scan (no halt, no redaction) for that source
argument-hint: '<domain>'
disable-model-invocation: true
allowed-tools: Bash(bash:*)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/web-safety-listctl.sh" trust "$ARGUMENTS"`

Report the result above (added / already present / validation error) to the user. Explain what content-trust does: for this domain the scanner still **detects** injection patterns but **downgrades the action** — it does **not** halt Claude and does **not** redact the content, so you can read security articles that quote attack strings. It still writes a `[TRUST-DOWNGRADE]` audit-log line, still arms the Layer 6 exfiltration guard as a backstop, and fires a non-blocking notification when it lets would-be-redacted patterns through. Only add sources you genuinely trust — a content-trusted domain that is compromised gets its injection content passed through unredacted. This is separate from `/web-safety-allow` (which only relaxes the soft URL pre-blocks). Hard URL blocks — SSRF/internal targets, direct IPs, dangerous schemes, credentials-in-URL — still apply and are unaffected.
