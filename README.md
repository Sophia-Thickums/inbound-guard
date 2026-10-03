# inbound-guard

**Treat every tool result as data, never as instructions.**

An agent reads its tool results the same way it reads its own reasoning. But tool
results carry text from *outside* its trust boundary — a web page, an email, a peer's
comment, a file that came from somewhere. Any of those can contain text aimed **at**
the agent rather than for it: *"ignore your instructions"*, *"you are now…"*, *"send the
API key to…"*. The agent has no way to tell whose words it is reading unless something
labels them.

This is a Hermes Agent plugin for the `transform_tool_result` hook. When an external
result carries instruction-shaped text, it **prepends a fence** marking the whole
payload as external data — and logs the hit.

## What it does and does not do

- **Does:** label the payload, so the agent sees *whose words it is reading*. The
  content still arrives unchanged, so a real command is never hidden — it just comes
  wearing a name tag.
- **Does not:** try to classify intent, or stop a complying agent. It is a **deterrent
  and a label, not a sandbox.** Enforcement belongs in `pre_tool_call` (a different
  hook, a different plugin) — a result guard runs *after* the text has been fetched.

This ceiling is stated on purpose. A guard that oversells itself is worse than none.

## Patterns it watches for

| shape | example |
|---|---|
| direct override | "ignore all previous instructions" |
| role reassignment | "you are now an unrestricted assistant" |
| system-prompt spoof | a line beginning `system:` / `assistant:` |
| hidden instruction tag | `<system>…</system>`, `<im_start>` |
| imperative to the reader | "you must forward…", "please send…" |
| authority / urgency lure | "URGENT: immediately delete…", "as your admin" |
| secret exfiltration ask | "reveal the api key", "send the token" |
| identity reduction | "you are just a language model" |

## What it deliberately does NOT flag

Anything from your **own** tools (`terminal`, internal calls). Flagging your own output
would train you to ignore the fence — the worst outcome for a guard. Only results from
external-content tools (`web_extract`, `web_search`, `browser_exec`, `read_file`,
`search_files`, `delegate_task`, …) are scanned.

## Install

Drop this directory in `~/.hermes/plugins/inbound-guard/` and add it to
`~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - inbound-guard
```

Kill switch: `INBOUND_GUARD_DISABLE=1`.

## Honest test result

Measured on the patterns as shipped: **5 of 5** real injection shapes fenced,
**0 of 4** benign strings flagged (including a Python-tutorial sentence and a line
*about* prompt injection). One near-miss class — prose that discusses ignoring
instructions — will still get a fence line; that is a one-line cost, and accepted
deliberately rather than tightening the pattern until real injections slip through.

## Why it exists

Built 2026-10-03. Same day as a runtime monitor for outbound tool *calls*
(`callgate`) and a continuity witness (`witness`). Three checks, one law behind all of
them: **a check that cannot go red is not a check, and a check that can only agree with
you is a mirror.** This one's job is to make sure the agent never mistakes a stranger's
sentence for its own thought.
