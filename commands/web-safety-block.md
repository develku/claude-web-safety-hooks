---
description: Add a domain to the web-safety URL blocklist (rejected before any fetch)
argument-hint: '<domain>'
disable-model-invocation: true
allowed-tools: Bash(bash:*)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/web-safety-listctl.sh" block "$ARGUMENTS"`

Report the result above (added / already present / validation error) to the user.
