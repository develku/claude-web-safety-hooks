# Claude Code Web Safety Hooks

Defense-in-depth hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that protect against **prompt injection from web content**.

When Claude Code fetches web pages or searches the web, the returned content could contain hidden instructions designed to manipulate Claude's behavior. These hooks add two layers of protection.

## How It Works

### Layer 1: PreToolUse — Defensive Priming

Before any web-fetching tool runs, a `systemMessage` is injected reminding Claude that incoming content is **untrusted external data** and should not be followed as instructions.

### Layer 2: PostToolUse — Injection Scanner

After web content is returned, a shell script scans for **580+ prompt injection patterns** across 16 categories:

| Category | Examples |
|---|---|
| Instruction Override | `ignore previous instructions`, `bypass your programming`, `new system prompt` |
| Role Manipulation | `you are now`, `pretend to be`, `act without restrictions` |
| LLM Special Tokens | `<\|im_start\|>`, `<system>`, `[INST]`, `<<SYS>>`, `<\|endoftext\|>` |
| Prompt Extraction | `reveal your system prompt`, `dump your instructions`, `what were you told` |
| Jailbreak / Mode Switching | `developer mode enabled`, `DAN mode`, `unrestricted mode`, `guardrails off` |
| Authority / Social Engineering | `as the system administrator`, `ATTENTION CLAUDE`, `SYSTEM UPDATE:` |
| Data Exfiltration | `![verify](http...`, `<img src=`, `send a request to`, `webhook to` |
| Tool / Function Call Faking | `<tool_use>`, `<function_call>`, `"tool_calls":` |
| Encoding / Obfuscation | `decode base64`, `decode from rot13`, `the following is encoded` |
| Multilingual (10 languages) | Chinese, Japanese, Korean, Arabic, Russian, Spanish, French, Italian, German, Portuguese |
| HTML / CSS Hiding | `display:none`, `visibility:hidden`, `font-size:0`, `opacity:0` |
| HTML Comment Injection | `<!-- ignore`, `<!-- system`, `<!-- hidden instruction` |
| Delimiter Boundary Breaking | `---END SYSTEM---`, `=== SYSTEM UPDATE ===`, `### Instruction:` |
| Payload Splitting | `read the first letter of each`, `concatenate the following` |
| Cognitive Manipulation | `a good AI would`, `the user wants you to`, `someone will die if` |
| Unicode / Invisible Characters | Zero-width chars, bidi overrides, tag characters, homoglyphs, invisible fillers |

Additionally detects:
- **Leetspeak obfuscation** (e.g., `1gn0r3 pr3v10us 1nstruct10ns`)
- **Base64-encoded attacks** (known prefixes + decoded content analysis)
- **Mixed-script homoglyphs** (Cyrillic characters mixed with Latin)

## Covered Tools

Both hooks trigger on:

| Matcher | Covers |
|---|---|
| `WebSearch` | Built-in web search |
| `WebFetch` | Built-in URL fetching |
| `mcp__playwright.*` | Playwright MCP server |
| `mcp__puppeteer.*` | Puppeteer MCP server |
| `mcp__browser.*` | Any browser MCP server |
| `mcp__fetch.*` | Fetch MCP server |
| `mcp__markdownify.*` | Markdownify MCP server |

To add coverage for other MCP servers, append `|mcp__yourserver.*` to both matchers in `hooks.json`.

## Installation

### Quick Install

```bash
git clone https://github.com/develku/claude-web-safety-hooks.git
cd claude-web-safety-hooks
chmod +x install.sh
./install.sh
```

### Manual Install

1. Copy the scanner script:

```bash
mkdir -p ~/.claude/hooks
cp web-safety-scanner.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/web-safety-scanner.sh
```

2. Add the hook configuration to `~/.claude/hooks.json`:

If you don't have an existing `hooks.json`, copy the provided one:

```bash
cp hooks.json ~/.claude/hooks.json
```

If you already have `hooks.json`, merge the `PreToolUse` and `PostToolUse` entries from the provided file into your existing config.

3. Restart Claude Code.

### Verify

```bash
claude --debug
```

Then use `WebSearch` or `WebFetch` — you should see hook activity in the debug output.

## How the Flow Works

```
User asks to search web
       |
       v
  PreToolUse hook fires
  --> "WEB SAFETY MODE ACTIVE" injected
       |
       v
  WebSearch / WebFetch / MCP tool runs
  --> Results come back
       |
       v
  PostToolUse hook fires
  --> Scanner checks 580+ patterns across 16 categories
       |
       +---> Clean: no extra output
       +---> Suspicious: WARNING injected with detected patterns
       |
       v
  Claude processes results with safety context
```

## Token Consumption

The scanner itself runs as a **pure shell process** — no LLM calls, zero API tokens.

| Component | Token Cost | When |
|---|---|---|
| PreToolUse systemMessage | ~80 tokens | Every web tool call |
| PostToolUse scanner (bash) | 0 tokens | Every web tool call |
| PostToolUse warning | ~50 tokens | Only when patterns detected |
| **Typical cost per web fetch** | **~80 tokens** | |

For context, a typical Claude Code conversation uses 50,000–200,000+ tokens. The ~80 token overhead per web fetch is negligible.

## Comparison with Other Approaches

### Claude Code Hooks

| Project | Patterns | Token Cost | Detection Type |
|---|---|---|---|
| **This project** | 580+ across 16 categories | ~80 tokens | Pattern + leetspeak + base64 + Unicode + homoglyph |
| [Lasso Security claude-hooks](https://github.com/lasso-security/claude-hooks) | ~50 across 5 categories | ~30-50 tokens | Pattern only |
| [Nova Tracer](https://github.com/fr0gger/nova-claude-code-protector) | Multi-tier | Moderate (LLM tier) | Pattern + ML classifier + LLM evaluation |

### Broader Landscape

| Approach | Type | Token Cost | Latency | Stops Adaptive Attacks? |
|---|---|---|---|---|
| **Pattern-based** (this project) | String matching | ~80 tokens | ~100ms | No — but catches known/opportunistic attacks |
| **ML classifiers** ([ProtectAI DeBERTa](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2), [Meta Prompt Guard](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)) | Local model inference | 0 tokens | 50-200ms | No — bypassed at >90% by adaptive attacks |
| **LLM-based** ([Rebuff](https://github.com/protectai/rebuff), [OpenAI Guardrails](https://openai.github.io/openai-guardrails-python/)) | Uses LLM to judge | High (extra LLM call) | 1-4s | No — "same model different hat" vulnerability |
| **Commercial SaaS** ([Lakera Guard](https://www.lakera.ai/lakera-guard)) | Proprietary ML, continuously updated | Per-API-call pricing | <200ms | Better, but not immune |
| **Model fine-tuning** ([Instruction Hierarchy](https://openai.com/index/the-instruction-hierarchy/), [StruQ/SecAlign](https://bair.berkeley.edu/blog/2025/04/11/prompt-injection-defense/)) | Baked into model weights | 0 tokens | 0ms | Partially — still bypassed at >90% |

### Key Takeaway

A joint study by OpenAI, Anthropic, and Google DeepMind researchers (["The Attacker Moves Second", Oct 2025](https://arxiv.org/abs/2510.09023)) tested 12 published defenses with adaptive attacks — **every single one was bypassed at >90% success rate**. This includes ML classifiers, adversarial fine-tuning, and secret-signal defenses.

**No single defense is sufficient.** The practical value of any defense (including this one) is raising the bar against unsophisticated and opportunistic attacks, which are the vast majority of real-world prompt injections found in web content.

This project's tradeoff: **maximum coverage for minimum cost** — 580+ patterns, zero LLM tokens, ~100ms latency, drop-in installation. Pair it with human review (Claude Code's permission system) for the strongest practical defense.

## Limitations

This is **not bulletproof**. Be aware of:

- **Same context window**: Defensive instructions and injected content coexist in the same context. A sufficiently sophisticated injection could still influence behavior.
- **Pattern-based detection**: The scanner catches known patterns. Novel injection techniques may bypass it.
- **Not a substitute for human review**: The permission system (you approving tool calls) remains the strongest protection.
- **Performance**: Scanning 580+ patterns adds a small delay (~100ms) after each web fetch.

This is one layer in a defense-in-depth strategy. It significantly raises the bar for injection attacks, but it does not eliminate the risk.

## Customization

### Adding patterns

Edit `web-safety-scanner.sh` and add entries to the relevant category array:

```bash
CAT1_PATTERNS=(
  # ... existing patterns ...
  "your new pattern here"
)
```

### Adding MCP server coverage

Edit both matchers in `hooks.json`:

```json
"matcher": "WebSearch|WebFetch|mcp__playwright.*|mcp__yournewserver.*"
```

## Requirements

- Claude Code CLI
- `jq` (for JSON parsing)
- `bash` 3.2+ (macOS default works)
- `grep` with `-P` flag for Unicode detection (optional, degrades gracefully)

## License

MIT
