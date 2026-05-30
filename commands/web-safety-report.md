---
description: Summarize the web-safety audit log — counts by severity, top tools and hosts, recent events
argument-hint: '[days]'
disable-model-invocation: true
allowed-tools: Bash(bash:*)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/web-safety-report.sh" "$ARGUMENTS"`

Present the script output above to the user verbatim — it is already formatted markdown. Do not summarize, re-interpret, or add commentary. The script is read-only (it never mutates the log). The optional argument is a number of days to limit the window (e.g. `7`).
