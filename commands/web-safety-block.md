---
description: Add a domain to the web-safety URL blocklist (rejected before any fetch)
argument-hint: "<domain>"
allowed-tools: Bash
---

The user wants to add a domain to the web-safety URL blocklist.

Run this bundled helper, which **validates** the domain before writing it to the blocklist consumed by the pre-screening hook:

!`bash "$CLAUDE_PLUGIN_ROOT/scripts/web-safety-listctl.sh" block $ARGUMENTS`

If the command above did not already run, execute it yourself with the Bash tool: `$CLAUDE_PLUGIN_ROOT/scripts/web-safety-listctl.sh block <domain>`. Report the result (added / already present / validation error) to the user.
