---
description: Add a trusted domain to the web-safety URL allowlist (relaxes soft-block heuristics)
argument-hint: '<domain>'
disable-model-invocation: true
allowed-tools: Bash(bash:*)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/web-safety-listctl.sh" allow "$ARGUMENTS"`

Report the result above (added / already present / validation error) to the user. Remind them: the allowlist only relaxes **soft** blocks (high-risk TLD, custom blocklist). Hard blocks — SSRF/internal targets, direct IP addresses, dangerous URI schemes, credentials-in-URL — still apply and cannot be allowlisted.
