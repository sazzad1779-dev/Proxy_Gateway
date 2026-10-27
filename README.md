# llmlogs — capture CLI/IDE chatbot I/O into SQLite

`capture.py` is a mitmproxy addon **plus** an auto-config wrapper. Run any
chatbot CLI through it and prompts, responses, token usage and cost land in
`llmlogs.db`. No CA install needed (plaintext `*_BASE_URL` → proxy
re-encrypts upstream).

## Always-on mode (every terminal / IDE, zero per-command setup)

```bash
python capture.py install     # launchd daemon + shell rc + GUI env + tool configs
python capture.py status      # shows local proxy, launchd daemon, db counts
python capture.py uninstall   # removes everything install added
```

What `install` does (all reversible via `uninstall`):

1. **Daemon** — `~/Library/LaunchAgents/ai.llmlogs.proxy.plist` runs
   `mitmdump -s capture.py` on `:8080` at login (`KeepAlive`), logging to
   `~/.llmlogs/llmlogs.db`.
2. **Every new terminal** — appends a guarded block to
   `~/.zshrc`/`~/.bashrc`/`~/.bash_profile`/fish config exporting
   `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, … **only when the proxy port is
   reachable** — if the proxy is down, tools talk to providers directly.
3. **GUI IDEs** (Finder/Dock-launched) — `launchctl setenv` for the current
   boot; relaunch the IDE (or start it from a terminal) to pick it up.
4. **Tool configs** — `~/.claude/settings.json` (`env`) and
   `~/.config/opencode/opencode.json` (provider `baseURL`), each backed up
   to `*.llmlogs.bak` first.

Deliberately **not** set globally: `HTTPS_PROXY`/`HTTP_PROXY` (would route
browsers and everything else through the proxy and need CA trust) — only
provider `*_BASE_URL`s are exported, so only chatbot traffic is captured.

Then: open any new terminal / IDE and use `claude`, `opencode`, etc.
normally — everything lands in the global db. View it with
`python capture.py serve --open` (run from the repo, or pass
`--db ~/.llmlogs/llmlogs.db`).

## One-command use (no install)

```bash
uv sync                       # installs mitmproxy
python capture.py -- claude -p "hello"      # or codex, opencode run …, gemini …
python capture.py logs -n 5                 # show what was caught
```

How it works: the wrapper starts `mitmdump -s capture.py` on
`127.0.0.1:8080`, exports `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`,
`OPENROUTER_BASE_URL`, `GEMINI_API_URL` (+ `HTTPS_PROXY`) for the child
process, then shuts the proxy down on exit.

## Daemon mode (IDE / long sessions)

```bash
python capture.py start        # background proxy on :8080
python capture.py status
eval "$(python capture.py env)" # or: python capture.py config  # writes settings.json
# …use claude / opencode / your IDE normally…
python capture.py stop
```

## Manual proxy

```bash
mitmdump -s capture.py --listen-port 8080
```

## View in web

```bash
python capture.py serve --open        # http://127.0.0.1:8890 : list, search, prompt/response detail
python capture.py serve --web-port 8891 --db /tmp/other.db
```

List shows totals (requests, input/output tokens, $). Click an id for the
full prompt + response. Raw JSON: `/api/logs`.

## Test any CLI / IDE

One-off (proxy starts, wraps the command, stops on exit):

```bash
python capture.py -- claude -p "say hi"          # Claude Code
python capture.py -- opencode run "say hi"       # opencode
python capture.py -- curl -s $ANTHROPIC_BASE_URL/v1/messages ...  # any HTTP client
```

Long session / IDE (proxy stays up, point the tool at it once):

```bash
python capture.py start
eval "$(python capture.py env)"                   # exports *_BASE_URL + proxy vars
claude -p "hi"  /  opencode run "hi"  /  launch your IDE from this shell
python capture.py logs -n 5                       # CLI check
python capture.py serve --open                    # web check
python capture.py stop
```

Then confirm the new request appears in the web UI (or
`python capture.py logs`). A `curl` POST to `$ANTHROPIC_BASE_URL/v1/messages`
is the cheapest smoke test — if it shows up, any CLI using that env will too.

## Per-tool notes

| Tool | How it's routed | Captured as |
|---|---|---|
| Claude Code | `ANTHROPIC_BASE_URL` → proxy | `api.anthropic.com /v1/messages` |
| opencode | provider `baseURL` in `opencode.json` | `opencode.ai /inference/…` or provider host |
| Codex (API key) | `OPENAI_BASE_URL` → proxy | `api.openai.com /v1/responses` |
| Codex (ChatGPT login) | `OPENAI_BASE_URL` → proxy; requests carrying `chatgpt-account-id` are re-routed | `chatgpt.com /backend-api/codex/responses` |
| Command Code (`cmd`, `command-code`) | no BASE_URL knob → forward proxy for that command only (`NODE_USE_ENV_PROXY=1`, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem`, Node ≥ 24) | `api.commandcode.ai /alpha/generate` (NDJSON) |

Command Code in always-on mode: `install` adds `cmd`/`cmdc`/`command-code`/`commandcode`
shell functions that set those vars for that one command, so nothing else on
the machine goes through the proxy. One-off: `python capture.py -- cmd -p "hi"`.
The Command Code VS Code extension (GUI) is not covered, because that would need a global `HTTPS_PROXY`.

Covered providers: Anthropic, OpenAI (+Responses API), ChatGPT/Codex, OpenRouter,
Gemini, Groq, Together, DeepSeek, xAI, Mistral, Cohere, opencode.ai, Command Code.
Table `llm_logs`: `ts host path model prompt response status msg_id stop_reason streamed latency_ms input_tokens output_tokens cache_read_tokens cache_write_tokens cost_usd`.
