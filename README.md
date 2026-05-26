<p align="center">
  <img src="attachments/logo.png" alt="Claude Web Safety Hooks" width="600">
</p>

# Claude Web Safety

Defense-in-depth hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that protect against **prompt injection from web content**. Distributed as a Claude Code plugin.

When Claude Code fetches web pages or searches the web, the returned content could contain hidden instructions designed to manipulate Claude's behavior. These hooks screen URLs before fetching, scan returned content against 600+ injection patterns across 8 evasion-resistant views, and surgically redact attacks before Claude sees them.

## How it works

Five layers, each documented in [docs/patterns.md](docs/patterns.md):

| Layer | When | What |
|---|---|---|
| **1. URL pre-screening** | PreToolUse | Block dangerous schemes, SSRF targets, IP addrs, credential leaks, open redirects, high-risk TLDs |
| **2. Severity-tiered scanner** | PostToolUse | 600+ patterns across HIGH/MEDIUM/LOW; 8 evasion views (whitespace, HTML entities, punctuation, Unicode confusables, URL-decoded, tag-stripped) |
| **3. Content sanitization** | PostToolUse | HIGH = full redaction; MEDIUM = surgical line-by-line; output capped at 50KB |
| **4. Cross-tool correlation + reassembly** | PostToolUse | 5-min window; 3+ flagged tools auto-escalate MEDIUM → HIGH. **v6.0+ also detects payloads split across multiple fetches** (`Part 1/3: ignore` + `Part 2/3: previous` + `Part 3/3: instructions` → reassembled match) |
| **5. Structural verification** | PostToolUse | Code-fence / YAML / JSON / HTML-code / inline-code aware — clears false positives like `assistant:` inside doc snippets without bothering the user |

## Install

```
/plugin marketplace add develku/claude-web-safety-hooks
/plugin install web-safety@develku
/reload-plugins
```

That's it. The matchers cover `WebFetch`, `WebSearch`, and a wide set of MCP web tools (Playwright, Puppeteer, Firecrawl, Exa, Context7, MCP Docker variants).

## Quick start

```bash
# (Optional) add a URL allowlist to skip the soft-block checks on trusted domains
mkdir -p ~/.claude/hooks
echo "github.com" >> ~/.claude/hooks/url-allowlist.txt
echo "anthropic.com" >> ~/.claude/hooks/url-allowlist.txt

# (Optional) add a URL blocklist
echo "malware-distribution.example.com" >> ~/.claude/hooks/url-blocklist.txt

# Trigger a test
# Ask Claude: "fetch https://blog.cyberdesserts.com/prompt-injection-attacks/"
# You should see a macOS notification (Basso/Sosumi/Ping per severity) and Claude pauses.

# Check the audit log
tail -20 ~/.claude/hooks/web-safety.log
```

See [docs/tuning.md](docs/tuning.md) for environment variables, severity tuning, allowlist/blocklist details, and false-positive workflow.

## Requirements

- Claude Code CLI
- `jq`, `bash` 3.2+, `perl`, `shasum`
- macOS for desktop notifications (scanner itself is cross-platform)

## Versions

See [CHANGELOG.md](CHANGELOG.md) for the per-version feature list. Latest is **6.2.0** — plugin-only installation; manual install path removed. Previous: **6.1.1** — confusable-letter bridge fix from stress testing. **6.1.0** — letter-boundary + affix-only limitation closures. **6.0.0** — cross-call payload reassembly (E8).

## Tests

```bash
./tests/run-tests.sh
```

34 tests (25 single-fetch + 9 multi-fetch sequences for cross-call reassembly) across HIGH/MEDIUM/LOW/legit/reassembly buckets, covering all 8 evasion views, Layer-5 false-positive guards, multi-pattern HIGH combinations, ordering-token reorder attacks, cross-session isolation, letter-boundary splits, 3-char affix-only fragments, and confusable-letter bridges. See [tests/README.md](tests/README.md).

## License

[MIT](LICENSE).
