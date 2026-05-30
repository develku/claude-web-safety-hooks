---
description: Summarize the web-safety audit log — counts by severity, top tools and hosts, recent events
argument-hint: "[days]"
allowed-tools: Bash
---

Show the user a summary of the web-safety audit log.

Run this bundled, **read-only** helper script and present its markdown output verbatim (do not summarize or re-interpret it):

!`bash "$CLAUDE_PLUGIN_ROOT/scripts/web-safety-report.sh" $ARGUMENTS`

If the command above did not already run, execute it yourself with the Bash tool — the script lives at `$CLAUDE_PLUGIN_ROOT/scripts/web-safety-report.sh` (this plugin's `scripts/` directory). The optional argument is a number of days to limit the window (e.g. `7`); pass through whatever the user gave, or nothing for the full log.
