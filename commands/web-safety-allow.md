---
description: Add a trusted domain to the web-safety URL allowlist (relaxes soft-block heuristics)
argument-hint: "<domain>"
allowed-tools: Bash
---

The user wants to add a domain to the web-safety URL allowlist.

Run this bundled helper, which **validates** the domain before writing it to the allowlist consumed by the pre-screening hook:

!`bash "$CLAUDE_PLUGIN_ROOT/scripts/web-safety-listctl.sh" allow $ARGUMENTS`

If the command above did not already run, execute it yourself with the Bash tool: `$CLAUDE_PLUGIN_ROOT/scripts/web-safety-listctl.sh allow <domain>`. Report the result (added / already present / validation error) to the user.

Remind the user: the allowlist only relaxes **soft** blocks (high-risk TLD, custom blocklist). Hard security blocks — SSRF/internal targets, direct IP addresses, dangerous URI schemes, credentials-in-URL — still apply and cannot be allowlisted.
