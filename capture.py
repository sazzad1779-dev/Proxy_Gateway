# capture.py — mitmproxy addon that logs LLM prompts, responses, token usage and cost.
# Works two ways:
#   1. Forward proxy (classic):  HTTPS_PROXY=http://127.0.0.1:8080 <cli>
#      intercepts TLS to real provider hosts (needs mitmproxy CA trusted).
#   2. BASE_URL rewrite (zero-cert, default for auto-config): the wrapper below
#      exports ANTHROPIC_BASE_URL=http://127.0.0.1:8080 etc. Requests arrive in
#      plaintext at the proxy; request() rewrites them to the real upstream
#      (https) before forwarding, so any chatbot CLI is caught with no CA setup.
#
#   mitmdump -s capture.py --listen-port 8080
#   python capture.py -- claude -p "hello"        # auto proxy + wrap any CLI
#   python capture.py start && claude -p "hello"  # daemon + manual use
import json
import os
import sqlite3
try:
    from mitmproxy import http
    from mitmproxy.net import encoding
    _MITM = True
except ImportError:  # running wrapper CLI in a venv without mitmproxy
    http = None  # type: ignore
    encoding = None  # type: ignore
    _MITM = False

PROXY_HOST = os.environ.get("LLMLOGS_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("LLMLOGS_PROXY_PORT", "8080"))
DB_PATH = os.environ.get("LLMLOGS_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "llmlogs.db"))
DEFAULT_UPSTREAM = os.environ.get("LLMLOGS_UPSTREAM", "api.anthropic.com")

HOSTS = {
    "api.anthropic.com",
    "api.openai.com",
    "opencode.ai",
    "api.openrouter.ai", "openrouter.ai",
    "generativelanguage.googleapis.com",
    "api.groq.com", "api.together.xyz", "api.deepseek.com", "api.x.ai",
    "api.mistral.ai", "api.cohere.ai",
    "chatgpt.com",          # Codex signed in with ChatGPT (backend-api/codex/responses)
    "api.commandcode.ai",   # Command Code (/alpha/generate, NDJSON stream)
}
# Hosts that mean "the client was pointed at the proxy via *_BASE_URL".
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
PATHS = ("/v1/messages", "/v1/responses", "/v1/chat/completions", "/v1/completions",
         "/v1/embeddings", "/v1beta/models", "/chat/completions", "/responses", "/messages",
         "/inference/",  # OpenCode Zen (opencode.ai/inference/…) — keep prefix in path
         "/alpha/generate")  # Command Code
SKIP_PATHS = ("count_tokens",)  # free endpoints, not generations
CHATGPT_CODEX = "/backend-api/codex"  # Codex with ChatGPT auth: base for /responses
MITM_CA = os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.pem")
# Node CLIs with no *_BASE_URL knob (Command Code) go through the proxy as a
# forward proxy instead: Node >=24 honours HTTPS_PROXY with NODE_USE_ENV_PROXY,
# and NODE_EXTRA_CA_CERTS makes it trust mitmproxy's CA.
FORWARD_PROXY_CLIS = ("cmd", "cmdc", "command-code", "commandcode")


def upstream_for(path: str) -> str:
    """Pick a real upstream host for requests sent directly to the proxy
    (BASE_URL=http://127.0.0.1:8080/...). Path-based so one port serves all.
    Returns a host, or a full URL (scheme://host:port) when LLMLOGS_UPSTREAM
    is set to one — used by tests with a local fake provider."""
    if "/v1/messages" in path:
        # Anthropic path always honours an explicit URL upstream (tests),
        # otherwise the real Anthropic API.
        if "://" in DEFAULT_UPSTREAM:
            return DEFAULT_UPSTREAM
        return "api.anthropic.com"
    if "/inference/" in path:
        return "opencode.ai"  # OpenCode Zen; path prefix preserved on rewrite
    if "/v1beta/models" in path:
        return "generativelanguage.googleapis.com"
    if "/v1/responses" in path or "/v1/chat/completions" in path or "/responses" in path:
        # OpenRouter-compatible chat endpoints default to OpenAI; override with
        # LLMLOGS_UPSTREAM if you point OPENROUTER_BASE_URL at the proxy.
        return DEFAULT_UPSTREAM if DEFAULT_UPSTREAM != "api.anthropic.com" else "api.openai.com"
    return DEFAULT_UPSTREAM


def apply_upstream(flow: "http.HTTPFlow", target: str):
    """Point flow at target host (or full scheme://host:port URL)."""
    if "://" in target:
        from urllib.parse import urlparse
        u = urlparse(target)
        flow.request.scheme = u.scheme or "https"
        if u.hostname:
            flow.request.host = u.hostname
        flow.request.port = u.port or (443 if flow.request.scheme == "https" else 80)
    else:
        flow.request.scheme = "https"
        flow.request.host = target
        flow.request.port = 443

# USD per 1M tokens: (input, output, cache_read). Anthropic first-party rates, 2026-09-25.
# Cache writes bill at 1.25x input (5m TTL) or 2x input (1h TTL).
PRICES = {
    "claude-fable-5-1":  (10.0, 50.0, 0.25),
    "claude-mythos-5-1": (10.0, 50.0, 0.25),
    "claude-fable-5":    (10.0, 50.0, 1.00),
    "claude-mythos-5":   (10.0, 50.0, 1.00),
    "claude-opus-5-5":   (4.0, 20.0, 0.20),
    "claude-opus-5":     (5.0, 25.0, 0.50),
    "claude-opus-4-8":   (5.0, 25.0, 0.50),
    "claude-opus-4-7":   (5.0, 25.0, 0.50),
    "claude-opus-4-6":   (5.0, 25.0, 0.50),
    "claude-sonnet-5-5": (2.0, 10.0, 0.20),
    "claude-sonnet-5":   (2.0, 10.0, 0.20),
    "claude-sonnet-4-6": (3.0, 15.0, 0.30),
    "claude-haiku-4-5":  (1.0, 5.0, 0.10),
}
_PRICE_KEYS = sorted(PRICES, key=len, reverse=True)  # longest prefix wins

COLUMNS = {  # added to older databases on startup
    "msg_id": "TEXT", "stop_reason": "TEXT", "streamed": "INTEGER", "latency_ms": "INTEGER",
    "input_tokens": "INTEGER", "output_tokens": "INTEGER",
    "cache_read_tokens": "INTEGER", "cache_write_tokens": "INTEGER", "cost_usd": "REAL",
}

db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA synchronous=NORMAL")
db.execute("""CREATE TABLE IF NOT EXISTS llm_logs(
  id INTEGER PRIMARY KEY, ts REAL, host TEXT, path TEXT,
  model TEXT, prompt TEXT, response TEXT, status INTEGER)""")
_have = {r[1] for r in db.execute("PRAGMA table_info(llm_logs)")}
for col, typ in COLUMNS.items():
    if col not in _have:
        db.execute(f"ALTER TABLE llm_logs ADD COLUMN {col} {typ}")
db.commit()


# ---------- usage + cost ----------

def new_usage() -> dict:
    return {"input": 0, "output": 0, "cache_read": 0, "cache_5m": 0, "cache_1h": 0, "speed": None}

def merge_usage(u: dict, raw: dict | None):
    """Fold a provider usage object into u. Later values override (Anthropic's
    message_delta carries cumulative counts)."""
    if not raw:
        return
    if raw.keys() & {"input_tokens", "output_tokens", "cache_read_input_tokens"}:  # Anthropic / OpenAI Responses
        cached = (raw.get("input_tokens_details") or {}).get("cached_tokens") or 0
        if raw.get("input_tokens") is not None:
            u["input"] = raw["input_tokens"] - cached                   # Responses counts cached inside input
        if cached:
            u["cache_read"] = cached
        if raw.get("cache_read_input_tokens") is not None:
            u["cache_read"] = raw["cache_read_input_tokens"]
        cc = raw.get("cache_creation") or {}
        if cc:
            u["cache_5m"] = cc.get("ephemeral_5m_input_tokens") or 0
            u["cache_1h"] = cc.get("ephemeral_1h_input_tokens") or 0
        elif raw.get("cache_creation_input_tokens") is not None:
            u["cache_5m"], u["cache_1h"] = raw["cache_creation_input_tokens"], 0
        if raw.get("output_tokens") is not None:
            u["output"] = raw["output_tokens"]
        if raw.get("speed"):
            u["speed"] = raw["speed"]
    elif "prompt_tokens" in raw:                                         # OpenAI chat completions
        cached = (raw.get("prompt_tokens_details") or {}).get("cached_tokens") or 0
        u["input"] = (raw.get("prompt_tokens") or 0) - cached
        u["cache_read"] = cached
        u["output"] = raw.get("completion_tokens") or 0
    elif "promptTokenCount" in raw:                                      # Gemini usageMetadata
        cached = raw.get("cachedContentTokenCount") or 0
        u["input"] = (raw.get("promptTokenCount") or 0) - cached
        u["cache_read"] = cached
        u["output"] = (raw.get("candidatesTokenCount") or 0) + (raw.get("thoughtsTokenCount") or 0)

def price_for(model: str | None):
    if not model:
        return None
    m = model.split("/")[-1].removeprefix("anthropic.")  # "anthropic/claude-…", Bedrock ids
    return next((PRICES[k] for k in _PRICE_KEYS if m.startswith(k)), None)

def cost_usd(model: str | None, u: dict) -> float | None:
    p = price_for(model)
    if p is None:
        return None
    p_in, p_out, p_read = p
    c = (u["input"] * p_in + u["cache_5m"] * p_in * 1.25 + u["cache_1h"] * p_in * 2
         + u["cache_read"] * p_read + u["output"] * p_out) / 1e6
    return c * 2 if u["speed"] == "fast" else c  # fast mode is 2x standard


# ---------- response parsing ----------

def _tool_text(name: str, args) -> str:
    if not isinstance(args, str):
        args = json.dumps(args, ensure_ascii=False)
    return f"[tool_use:{name}] {args}"

def parse_sse(text: str) -> dict:
    blocks: dict[int, dict] = {}   # Anthropic content blocks by index
    out: list[str] = []            # other providers' text deltas
    meta = {"usage": new_usage(), "model": None, "msg_id": None, "stop_reason": None}
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            ev = json.loads(payload)
        except ValueError:
            continue
        t = ev.get("type", "")
        if t == "message_start":                                # Anthropic
            msg = ev.get("message", {})
            meta["model"], meta["msg_id"] = msg.get("model"), msg.get("id")
            merge_usage(meta["usage"], msg.get("usage"))
        elif t == "content_block_start":
            cb = ev.get("content_block", {})
            blocks[ev.get("index", 0)] = {"type": cb.get("type"), "name": cb.get("name"), "parts": [cb.get("text", "")]}
        elif t == "content_block_delta":
            d = ev.get("delta", {})
            b = blocks.setdefault(ev.get("index", 0), {"type": "text", "name": None, "parts": []})
            b["parts"].append(d.get("text") or d.get("partial_json") or "")
        elif t == "message_delta":
            meta["stop_reason"] = ev.get("delta", {}).get("stop_reason") or meta["stop_reason"]
            merge_usage(meta["usage"], ev.get("usage"))
        elif t == "response.output_text.delta":                 # OpenAI Responses API
            out.append(ev.get("delta", ""))
        elif t == "response.output_item.done":
            item = ev.get("item") or {}
            if item.get("type") == "function_call":
                out.append("\n" + _tool_text(item.get("name"), item.get("arguments", "")) + "\n")
        elif t == "response.completed":
            r = ev.get("response", {})
            meta["model"], meta["msg_id"] = r.get("model"), r.get("id")
            meta["stop_reason"] = r.get("status")
            merge_usage(meta["usage"], r.get("usage"))
        elif "choices" in ev or "candidates" in ev:             # chat completions / OpenRouter / Gemini
            meta["model"] = ev.get("model") or ev.get("modelVersion") or meta["model"]
            meta["msg_id"] = ev.get("id") or ev.get("responseId") or meta["msg_id"]
            for ch in ev.get("choices") or []:
                out.append((ch.get("delta") or {}).get("content") or "")
                meta["stop_reason"] = ch.get("finish_reason") or meta["stop_reason"]
            for cand in ev.get("candidates") or []:
                out.extend(p.get("text", "") for p in cand.get("content", {}).get("parts", []))
                meta["stop_reason"] = cand.get("finishReason") or meta["stop_reason"]
            merge_usage(meta["usage"], ev.get("usage") or ev.get("usageMetadata"))

    parts = []
    for _, b in sorted(blocks.items()):
        body = "".join(b["parts"])
        if b["type"] == "text":
            parts.append(body)
        elif b["type"] in ("tool_use", "server_tool_use"):
            parts.append(_tool_text(b["name"], body))
    parts.append("".join(out))
    meta["text"] = "\n".join(p for p in parts if p)
    return meta

def parse_ndjson(text: str) -> dict:
    """Vercel AI SDK fullStream as NDJSON (Command Code /alpha/generate)."""
    out: list[str] = []
    meta = {"usage": new_usage(), "model": None, "msg_id": None, "stop_reason": None}
    for line in text.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        t = ev.get("type")
        if t == "text-delta":
            out.append(ev.get("text") or ev.get("delta") or "")
        elif t == "tool-call":
            out.append("\n" + _tool_text(ev.get("toolName"), ev.get("input", ev.get("args"))) + "\n")
        elif t == "finish":
            meta["stop_reason"] = ev.get("rawFinishReason") or ev.get("finishReason")
            tu = ev.get("totalUsage") or {}
            d = tu.get("inputTokenDetails") or {}
            u = meta["usage"]
            u["cache_read"] = d.get("cacheReadTokens") or 0
            u["cache_5m"] = d.get("cacheWriteTokens") or 0
            u["input"] = d.get("noCacheTokens", (tu.get("inputTokens") or 0) - u["cache_read"] - u["cache_5m"])
            u["output"] = tu.get("outputTokens") or 0
        elif t == "error":
            out.append(f"[error] {json.dumps(ev.get('error', ev), ensure_ascii=False)}")
    meta["text"] = "".join(out).strip()
    return meta

def parse_json(text: str) -> dict:
    d = json.loads(text)
    meta = {"usage": new_usage(), "model": d.get("model"), "msg_id": d.get("id"),
            "stop_reason": d.get("stop_reason"), "text": ""}
    merge_usage(meta["usage"], d.get("usage") or d.get("usageMetadata"))
    if isinstance(d.get("content"), list):                     # Anthropic
        meta["text"] = "\n".join(
            b.get("text", "") if b.get("type") == "text" else _tool_text(b.get("name"), b.get("input"))
            for b in d["content"] if b.get("type") in ("text", "tool_use", "server_tool_use"))
    elif d.get("choices"):                                      # chat completions
        ch = d["choices"][0]
        meta["text"] = (ch.get("message") or {}).get("content") or ""
        meta["stop_reason"] = ch.get("finish_reason")
    elif "output" in d:                                         # OpenAI Responses
        meta["text"] = "".join(c.get("text", "") for o in d["output"] if o.get("type") == "message"
                               for c in o.get("content", []))
        meta["stop_reason"] = d.get("status")
    elif "error" in d:
        meta["text"] = json.dumps(d["error"], ensure_ascii=False)
    return meta


# ---------- request parsing ----------

def _block_text(b) -> str:
    if isinstance(b, str):
        return b
    if not isinstance(b, dict):
        return ""
    t = b.get("type")
    if t in ("text", "input_text"):
        return b.get("text", "")
    if t == "tool_result":
        c = b.get("content")
        inner = c if isinstance(c, str) else "".join(_block_text(x) for x in c or [])
        return f"[tool_result] {inner}"
    if t in ("image", "document", "input_image", "input_file"):
        return f"[{t}]"
    return ""

def last_user_text(body: dict) -> str:
    msgs = body.get("messages") or body.get("input") or body.get("contents") or []
    if isinstance(msgs, str):
        return msgs
    for m in reversed(msgs):
        if isinstance(m, dict) and m.get("role") == "user":
            c = m.get("content", m.get("parts"))
            if isinstance(c, str):
                return c
            return "\n".join(s for s in map(_block_text, c or []) if s)
    return ""


# ---------- mitmproxy hooks ----------

def is_target(flow: "http.HTTPFlow") -> bool:
    host = flow.request.pretty_host
    # Direct-to-proxy hits (client used *_BASE_URL=http://127.0.0.1:8080) count
    # as targets based on path alone; request() rewrites them upstream.
    if host in LOCAL_HOSTS:
        path = flow.request.path
        return (flow.request.method == "POST"
                and any(p in path for p in PATHS)
                and not any(s in path for s in SKIP_PATHS))
    path = flow.request.path
    return (host in HOSTS
            and flow.request.method == "POST"
            and any(p in path for p in PATHS)
            and not any(s in path for s in SKIP_PATHS))

def request(flow: "http.HTTPFlow"):
    if flow.request.pretty_host in LOCAL_HOSTS and flow.request.method == "POST":
        path = flow.request.path
        if any(p in path for p in PATHS) and not any(s in path for s in SKIP_PATHS):
            # Rewrite BASE_URL-style plaintext hits to the real https upstream so
            # one proxy port serves every provider with no CA install.
            if "chatgpt-account-id" in flow.request.headers and "/responses" in path:
                # Codex logged in with ChatGPT: its OAuth token only works on
                # chatgpt.com/backend-api/codex, not api.openai.com.
                flow.request.path = CHATGPT_CODEX + path[path.index("/responses"):]
                target = "chatgpt.com"
            else:
                target = upstream_for(flow.request.path)
            apply_upstream(flow, target)
    if is_target(flow):
        # avoid gzip/brotli/zstd so streamed chunks stay readable
        flow.request.headers["accept-encoding"] = "identity"

def responseheaders(flow: "http.HTTPFlow"):
    if not is_target(flow):
        return
    buf: list[bytes] = []
    flow.metadata["chunks"] = buf
    def tap(data: bytes) -> bytes:
        buf.append(data)
        return data          # pass through untouched
    flow.response.stream = tap

def response(flow: "http.HTTPFlow"):
    if not is_target(flow):
        return
    try:
        body = json.loads(flow.request.get_text() or "")
    except ValueError:
        return

    raw = b"".join(flow.metadata.get("chunks") or []) or (flow.response.raw_content or b"")
    enc = flow.response.headers.get("content-encoding", "identity")
    if enc != "identity":
        try:
            raw = encoding.decode(raw, enc)
        except ValueError:
            pass
    text = raw.decode("utf-8", errors="replace")

    ctype = flow.response.headers.get("content-type", "")
    ndjson = "/alpha/generate" in flow.request.path and "application/json" not in ctype
    streamed = ndjson or "text/event-stream" in ctype
    if isinstance(body.get("params"), dict):  # Command Code wraps the model call in params
        body = body["params"]
    try:
        meta = parse_ndjson(text) if ndjson else parse_sse(text) if streamed else parse_json(text)
    except ValueError:
        meta = {"usage": new_usage(), "model": None, "msg_id": None, "stop_reason": None, "text": text}

    model = meta["model"] or body.get("model")   # served model (reflects fallbacks) when available
    u = meta["usage"]
    end = flow.response.timestamp_end or flow.response.timestamp_start
    db.execute(
        """INSERT INTO llm_logs(ts,host,path,model,prompt,response,status,msg_id,stop_reason,streamed,
             latency_ms,input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,cost_usd)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (flow.request.timestamp_start, flow.request.pretty_host, flow.request.path, model,
         last_user_text(body), meta["text"], flow.response.status_code, meta["msg_id"],
         meta["stop_reason"], int(streamed),
         int((end - flow.request.timestamp_start) * 1000) if end else None,
         u["input"], u["output"], u["cache_read"], u["cache_5m"] + u["cache_1h"],
          cost_usd(model, u)))
    db.commit()


# ---------- auto-config wrapper: catch any chatbot CLI ----------
# Only runs when executed as `python capture.py ...`, NOT when loaded by mitmdump.
ADDON_PATH = os.path.abspath(__file__)
PIDFILE = os.path.join(os.path.dirname(ADDON_PATH), ".llmlogs-proxy.pid")


def proxy_base(port: int) -> str:
    return f"http://{PROXY_HOST}:{port}"


def proxy_env(port: int, extra_upstream: str | None = None) -> dict:
    """Env that routes chatbot CLIs through the proxy with no CA setup.

    BASE_URL rewrites are the primary catch (plaintext client->proxy, proxy
    re-encrypts upstream). HTTPS_PROXY is added too so tools that honour it
    (curl, python httpx, some CLIs) are caught even without a BASE_URL knob.
    """
    base = f"http://{PROXY_HOST}:{port}"
    up = extra_upstream or DEFAULT_UPSTREAM
    env = {
        "ANTHROPIC_BASE_URL": base,            # claude code, anthropic SDK
        "ANTHROPIC_API_URL": base,
        "OPENAI_BASE_URL": base + "/v1",       # codex, openai SDK, compatibles
        "OPENAI_API_BASE": base + "/v1",
        "OPENROUTER_BASE_URL": base + "/v1",
        "GEMINI_API_URL": base + "/v1beta",
        "GOOGLE_GEMINI_BASE_URL": base + "/v1beta",
        "LLMLOGS_PROXY_PORT": str(port),
        "LLMLOGS_UPSTREAM": up,
        # Forward-proxy catch for anything honouring std proxy vars.
        # Plain http (not https) proxy URL avoids a TLS handshake with the
        # proxy itself, so no CA is needed client-side for http BASE_URLs.
        "HTTP_PROXY": base,
        "HTTPS_PROXY": base,
        "http_proxy": base,
        "https_proxy": base,
        "NO_PROXY": "",
        "no_proxy": "",
        # Node CLIs without a BASE_URL knob (Command Code): honour the proxy
        # vars above and trust mitmproxy's CA for the TLS it re-signs.
        "NODE_USE_ENV_PROXY": "1",
        "NODE_EXTRA_CA_CERTS": MITM_CA,
    }
    return env


def forward_proxy_env(port: int) -> dict:
    """Per-command env for FORWARD_PROXY_CLIS in always-on mode (never global)."""
    base = proxy_base(port)
    return {"NODE_USE_ENV_PROXY": "1", "HTTPS_PROXY": base, "HTTP_PROXY": base,
            "NO_PROXY": "localhost,127.0.0.1,::1", "NODE_EXTRA_CA_CERTS": MITM_CA}


def _proxy_cmd(port: int, db_path: str) -> list:
    return ["mitmdump", "-s", ADDON_PATH, "--listen-host", PROXY_HOST,
            "-p", str(port), "-q"]


def start_proxy(port: int, db_path: str, upstream: str | None = None) -> "subprocess.Popen":
    import subprocess
    env = dict(os.environ)
    env["LLMLOGS_DB"] = db_path
    env["LLMLOGS_PROXY_PORT"] = str(port)
    if upstream:
        env["LLMLOGS_UPSTREAM"] = upstream
    proc = subprocess.Popen(_proxy_cmd(port, db_path), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(PIDFILE, "w") as f:
        f.write(f"{proc.pid} {port}")
    return proc


def wait_for_proxy(port: int, timeout: float = 15.0) -> bool:
    import socket
    import time
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection((PROXY_HOST, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def stop_proxy() -> bool:
    import signal
    try:
        with open(PIDFILE) as f:
            pid = int(f.read().strip().split()[0])
        os.kill(pid, signal.SIGTERM)
        os.remove(PIDFILE)
        return True
    except (FileNotFoundError, ProcessLookupError, ValueError):
        try:
            os.remove(PIDFILE)
        except OSError:
            pass
        return False


def proxy_running() -> bool:
    try:
        with open(PIDFILE) as f:
            pid = int(f.read().strip().split()[0])
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ProcessLookupError, ValueError, PermissionError):
        return False


def main_cli(argv: list | None = None) -> int:
    import argparse
    import subprocess
    ap = argparse.ArgumentParser(
        description="Capture CLI/IDE chatbot I/O (Claude Code, Codex, OpenCode, …) "
                    "into llmlogs.db via a local mitmproxy.")
    ap.add_argument("--port", type=int, default=PROXY_PORT)
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--upstream", default=DEFAULT_UPSTREAM,
                    help="default https host for bare BASE_URL hits (default: api.anthropic.com)")
    ap.add_argument("--web-port", type=int, default=int(os.environ.get("LLMLOGS_WEB_PORT", "8890")),
                    help="port for `serve` web UI (default: 8890)")
    # Split off wrapped command BEFORE argparse so `curl`, `claude`, … are never
    # mistaken for our own subcommands (`start|stop|…`).
    if argv is None:
        import sys as _sys
        argv = _sys.argv[1:]
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1:]
    else:
        rest = []
    import argparse as _ap
    # Global flags (--port/--db/--upstream/--web-port) normally go BEFORE the
    # subcommand; repeat them on subparsers (SUPPRESS keeps the global value
    # when the flag is absent) so `serve --db X` etc. also work.
    _G = {"--port": {"type": int}, "--db": {}, "--upstream": {}}
    sub = ap.add_subparsers(dest="cmd")
    st = sub.add_parser("start", help="start proxy daemon in background")
    for f, kw in _G.items():
        st.add_argument(f, default=_ap.SUPPRESS, **kw)
    sub.add_parser("stop", help="stop proxy daemon")
    ss = sub.add_parser("status", help="show proxy status")
    ss.add_argument("--port", type=int, default=_ap.SUPPRESS)
    ss.add_argument("--db", default=_ap.SUPPRESS)
    lg = sub.add_parser("logs", help="tail recent logged prompts")
    lg.add_argument("-n", type=int, default=5)
    lg.add_argument("--db", default=_ap.SUPPRESS)
    en = sub.add_parser("env", help="print export lines for manual use")
    en.add_argument("--port", type=int, default=_ap.SUPPRESS)
    en.add_argument("--upstream", default=_ap.SUPPRESS)
    cf = sub.add_parser("config", help="write settings.json + opencode.json provider entries")
    cf.add_argument("--port", type=int, default=_ap.SUPPRESS)
    ins = sub.add_parser("install", help="always-on mode: daemon + every terminal/IDE auto-routed")
    ins.add_argument("--no-launchd", action="store_true")
    ins.add_argument("--no-shell", action="store_true")
    ins.add_argument("--no-config", action="store_true")
    ins.add_argument("--global-db", default=None,
                     help="canonical db for global mode (default: ~/.llmlogs/llmlogs.db)")
    ins.add_argument("--port", type=int, default=_ap.SUPPRESS)
    ins.add_argument("--upstream", default=_ap.SUPPRESS)
    sub.add_parser("uninstall", help="remove everything install added")
    sv = sub.add_parser("serve", help="web UI for llmlogs.db (no extra deps)")
    sv.add_argument("--open", action="store_true", help="open browser automatically")
    # accept `--web-port`/`--db` after `serve` too (global flags normally go before it)
    sv.add_argument("--web-port", type=int, default=_ap.SUPPRESS)
    sv.add_argument("--db", default=_ap.SUPPRESS)
    args = ap.parse_args(argv)

    if args.cmd == "stop":
        print("stopped" if stop_proxy() else "not running")
        return 0
    if args.cmd == "status":
        print(f"local proxy: {'running' if proxy_running() else 'not running'}"
              f" ({PROXY_HOST}:{args.port})")
        print(f"global daemon (launchd {PLIST_LABEL}): "
              f"{'loaded' if _launchd_loaded() else 'not loaded'}"
              + (f" — {PLIST_PATH}" if os.path.exists(PLIST_PATH) else ""))
        for label, dbp in (("local db", args.db), ("global db", GLOBAL_DB)):
            if os.path.exists(dbp):
                import sqlite3 as _s2
                try:
                    n = _s2.connect(dbp).execute("SELECT COUNT(*) FROM llm_logs").fetchone()[0]
                    print(f"{label} {dbp}: {n} requests")
                except Exception as e:
                    print(f"{label} {dbp}: unreadable ({e})")
            else:
                print(f"{label} {dbp}: no db yet")
        if not proxy_running() and not _launchd_loaded():
            print("run: python capture.py install   # always-on, every terminal/IDE")
        return 0
    if args.cmd == "logs":
        import sqlite3 as _s
        con = _s.connect(args.db)
        rows = con.execute(
            "SELECT datetime(ts,'unixepoch','localtime'), model, substr(prompt,1,80), "
            "input_tokens, output_tokens, cost_usd FROM llm_logs ORDER BY id DESC LIMIT ?",
            (args.n,)).fetchall()
        for r in rows:
            print(r)
        return 0
    if args.cmd == "env":
        for k, v in proxy_env(args.port, args.upstream).items():
            print(f"export {k}={v}")
        return 0
    if args.cmd == "config":
        _write_configs(args.port)
        return 0
    if args.cmd == "install":
        return install_global(args.port, args.global_db or GLOBAL_DB, args.upstream,
                              do_launchd=not args.no_launchd,
                              do_shell=not args.no_shell,
                              do_configs=not args.no_config)
    if args.cmd == "uninstall":
        return uninstall_global()
    if args.cmd == "serve":
        serve_web(args.db, args.web_port, open_browser=args.open)
        return 0
    if args.cmd == "start":
        if proxy_running():
            print(f"already running on {PROXY_HOST}:{args.port}")
            return 0
        start_proxy(args.port, args.db, args.upstream)
        print("waiting for proxy…" if not wait_for_proxy(args.port) else
              f"proxy on {PROXY_HOST}:{args.port}, db={args.db}\n"
              f"run: python capture.py -- <your-chatbot-cli>")
        return 0

    # Default: launch proxy, run wrapped command (or foreground proxy if none).
    env = dict(os.environ)
    env.update(proxy_env(args.port, args.upstream))
    env["LLMLOGS_DB"] = args.db
    proc = None
    if not proxy_running():
        proc = start_proxy(args.port, args.db, args.upstream)
        if not wait_for_proxy(args.port):
            print("proxy failed to start (is mitmdump installed?)")
            proc.terminate()
            return 1
    try:
        if not rest:
            print(f"proxy on {PROXY_HOST}:{args.port} → db {args.db} (Ctrl-C to stop)")
            print("example: python capture.py -- claude -p \"hello\"")
            try:
                import time
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
            return 0
        print(f"[llmlogs] proxy={PROXY_HOST}:{args.port} wrapping: {' '.join(rest)}")
        return subprocess.run(rest, env=env).returncode
    finally:
        if proc is not None:  # we started it → shut down; `start` daemon stays up
            proc.terminate()
            try:
                os.remove(PIDFILE)
            except OSError:
                pass


def serve_web(db_path: str, port: int, open_browser: bool = False):
    """Dependency-free web UI for llmlogs.db: list, search, detail, totals."""
    import html
    import sqlite3 as _s
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    def q(sql, a=()):
        con = _s.connect(db_path)
        try:
            return con.execute(sql, a).fetchall()
        finally:
            con.close()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body: str, code: int = 200, ctype: str = "text/html; charset=utf-8"):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            if u.path == "/api/logs":
                rows = q("SELECT id, ts, model, prompt, response, input_tokens,"
                         " output_tokens, cost_usd FROM llm_logs ORDER BY id DESC LIMIT 200")
                import json as _j
                self._send(_j.dumps([dict(zip(
                    ("id", "ts", "model", "prompt", "response",
                     "input_tokens", "output_tokens", "cost_usd"), r)) for r in rows]),
                    ctype="application/json")
                return
            if u.path == "/" and qs.get("id"):
                try:
                    row = q("SELECT id, datetime(ts,'unixepoch','localtime'), host, path, model,"
                            " prompt, response, status, stop_reason, input_tokens, output_tokens,"
                            " cache_read_tokens, cache_write_tokens, cost_usd, latency_ms"
                            " FROM llm_logs WHERE id=?", (int(qs["id"][0]),))
                except ValueError:
                    row = []
                if not row:
                    self._send("<p>not found. <a href='/'>back</a></p>", 404)
                    return
                (i, ts, host, path, model, prompt, resp, st, stop,
                 it, ot, cr, cw, cost, lat) = row[0]
                self._send(f"""<!doctype html><meta charset=utf-8><meta name=viewport
 content="width=device-width,initial-scale=1"><title>llmlogs #{i}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
pre{{background:#f4f4f5;padding:1rem;white-space:pre-wrap;border-radius:8px}}a{{color:#2563eb}}</style>
<p><a href="/">← all logs</a></p><h2>#{i} {html.escape(model or '')}</h2>
<p>{html.escape(str(ts))} · {html.escape(host or '')}{html.escape(path or '')} · status {st}
 · in {it} / out {ot} / cache_r {cr} / cache_w {cw} · ${cost or 0:.6f} · {lat}ms · stop {html.escape(str(stop))}</p>
<h3>prompt</h3><pre>{html.escape(prompt or '')}</pre><h3>response</h3><pre>{html.escape(resp or '')}</pre>""")
                return
            filt = (qs.get("q") or [""])[0]
            like = f"%{filt}%"
            rows = q("SELECT id, datetime(ts,'unixepoch','localtime'), model,"
                     " substr(prompt,1,120), input_tokens, output_tokens, cost_usd"
                     " FROM llm_logs WHERE prompt LIKE ? OR response LIKE ? OR model LIKE ?"
                     " ORDER BY id DESC LIMIT 200", (like, like, like))
            tot = q("SELECT COUNT(*), COALESCE(SUM(input_tokens),0),"
                    " COALESCE(SUM(output_tokens),0), COALESCE(SUM(cost_usd),0) FROM llm_logs")
            n, ti, to, tc = tot[0] if tot else (0, 0, 0, 0)
            items = "".join(
                f"<tr><td><a href='/?id={r[0]}'>#{r[0]}</a></td><td>{html.escape(str(r[1]))}</td>"
                f"<td>{html.escape(r[2] or '')}</td><td>{html.escape(r[3] or '')}</td>"
                f"<td>{r[4]}/{r[5]}</td><td>${r[6] or 0:.6f}</td></tr>" for r in rows)
            self._send(f"""<!doctype html><meta charset=utf-8><meta name=viewport
 content="width=device-width,initial-scale=1"><title>llmlogs</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #e4e4e7;padding:.4rem;text-align:left;font-size:.85rem}}
form{{margin:1rem 0}}input{{padding:.4rem;width:300px}}a{{color:#2563eb}}</style>
<h1>llmlogs</h1><p>{n} requests · {ti} in / {to} out tokens · ${tc:.4f} total</p>
<form><input name=q placeholder="search prompt / response / model" value="{html.escape(filt)}">
<button>search</button></form>
<table><tr><th>id</th><th>time</th><th>model</th><th>prompt…</th><th>in/out</th><th>cost</th></tr>{items}</table>
<p><a href="/api/logs">JSON: /api/logs</a></p>""")

    srv = HTTPServer(("127.0.0.1", port), H)
    url = f"http://127.0.0.1:{port}/"
    print(f"llmlogs web UI → {url}  (db={db_path}, Ctrl-C to stop)")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def _write_configs(port: int):
    """Write IDE/CLI config files so traffic flows through the proxy."""
    base = proxy_base(port)
    here = os.path.dirname(ADDON_PATH)
    sj = os.path.join(here, "settings.json")
    try:
        cur = json.load(open(sj)) if os.path.exists(sj) else {}
    except ValueError:
        cur = {}
    cur.setdefault("env", {}).update(proxy_env(port))
    try:
        json.dump(cur, open(sj, "w"), indent=2)
    except OSError as e:
        print(f"could not write {sj}: {e} (run with sudo or chown the file)")
        return
    print(f"wrote {sj} (ANTHROPIC_BASE_URL={base} …)")
    oj = os.path.join(os.path.expanduser("~"), ".config", "opencode", "opencode.json")
    try:
        if os.path.exists(oj):
            print(f"opencode config exists at {oj}; add a provider with baseUrl={base} manually")
        else:
            print(f"no {oj} found; set OPENAI_BASE_URL={base}/v1 or run via wrapper")
    except OSError as e:
        print(f"opencode check skipped: {e}")


# ---------- always-on global mode (every terminal / IDE on this machine) ----------
GLOBAL_DIR = os.path.join(os.path.expanduser("~"), ".llmlogs")
GLOBAL_DB = os.path.join(GLOBAL_DIR, "llmlogs.db")
PLIST_LABEL = "ai.llmlogs.proxy"
PLIST_PATH = os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents",
                           f"{PLIST_LABEL}.plist")
RC_MARK_START = "# >>> llmlogs >>>"
RC_MARK_END = "# <<< llmlogs <<<"
INSTALL_RECEIPT = os.path.join(GLOBAL_DIR, "install.json")


def _claude_ours(port: int) -> dict:
    """Key-paths → values install writes into ~/.claude/settings.json."""
    return {("env", k): v for k, v in proxy_env(port).items()
            if k in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL")}


def _opencode_ours(port: int) -> dict:
    """Key-paths → values install writes into opencode.json."""
    base = proxy_base(port)
    suffix = {"anthropic": "", "openai": "/v1", "openrouter": "/v1",
              "opencode": "/inference/openai/v1"}  # Zen keeps its path prefix
    return {("provider", pid, "options", "baseURL"): base + sfx
            for pid, sfx in suffix.items()}


def _cfg_get(d: dict, kp: tuple):
    cur = d
    for k in kp:
        if not isinstance(cur, dict) or k not in cur:
            return None, False
        cur = cur[k]
    return cur, True


def _cfg_del(d: dict, kp: tuple):
    """Delete nested key, pruning dicts left empty. Returns True if removed."""
    stack = [d]
    for k in kp[:-1]:
        nxt = stack[-1].get(k)
        if not isinstance(nxt, dict):
            return False
        stack.append(nxt)
    if kp[-1] not in stack[-1]:
        return False
    del stack[-1][kp[-1]]
    for i in range(len(stack) - 1, 0, -1):
        if stack[i] == {}:
            del stack[i - 1][kp[i - 1]]
        else:
            break
    return True


def _cfg_set(d: dict, kp: tuple, val):
    for k in kp[:-1]:
        d = d.setdefault(k, {})
    d[kp[-1]] = val


def _revert_tool_config(path: str, ours: dict) -> str:
    """Undo exactly what install added: for each key we set, if it still holds
    our value, restore the pre-install (.bak) value or delete it. Keys the user
    changed afterwards are left alone."""
    if not os.path.exists(path):
        return "absent (nothing to revert)"
    try:
        cur = json.load(open(path))
    except ValueError:
        return "FAILED (not valid JSON — left untouched)"
    bak_path = path + ".llmlogs.bak"
    bak = None
    if os.path.exists(bak_path):
        try:
            bak = json.load(open(bak_path))
        except ValueError:
            bak = None
    touched, skipped = 0, 0
    for kp, our_val in ours.items():
        cur_val, found = _cfg_get(cur, kp)
        if not found or cur_val != our_val:
            if found:
                skipped += 1  # user customized after install → keep
            continue
        bak_val, bak_found = _cfg_get(bak, kp) if isinstance(bak, dict) else (None, False)
        if bak_found:
            _cfg_set(cur, kp, bak_val)
        else:
            _cfg_del(cur, kp)
        touched += 1
    if touched:
        json.dump(cur, open(path, "w"), indent=2)
    if bak is not None and cur == bak:
        os.remove(bak_path)
        return f"restored original ({touched} keys reverted, backup removed)"
    extra = f", {skipped} kept (customized after install)" if skipped else ""
    return f"reverted {touched} of our keys{extra}" if touched else (
        "already clean" if not skipped else f"nothing of ours left{extra}")


def _mitmdump_bin() -> str | None:
    """Find a mitmdump binary that also works headless under launchd.

    Skips `.venv` shims (their interpreter can be denied files when started
    by launchd) and prefers stable per-user installs."""
    import shutil
    cands = []
    for p in os.environ.get("PATH", "").split(os.pathsep):
        if ".venv" in p or not p:
            continue
        full = os.path.join(p, "mitmdump")
        if os.path.isfile(full):
            cands.append(full)
    cands += [os.path.expanduser("~/.local/bin/mitmdump"),
              "/opt/homebrew/bin/mitmdump", "/usr/local/bin/mitmdump"]
    seen = set()
    for c in cands:
        c = os.path.realpath(c)
        if c in seen:
            continue
        seen.add(c)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return shutil.which("mitmdump")


_RC_SKIP = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy",
            "LLMLOGS_PROXY_PORT", "LLMLOGS_UPSTREAM", "NODE_USE_ENV_PROXY", "NODE_EXTRA_CA_CERTS")


def _rc_sh_block(port: int, db: str) -> str:
    lines = [RC_MARK_START,
             "# Route chatbot CLIs (claude, opencode, …) through the llmlogs proxy when it's up.",
             "# Safe: if the proxy is down, tools talk to providers directly.",
             f'if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 {port} 2>/dev/null; then']
    for k, v in proxy_env(port).items():
        if k in _RC_SKIP:
            continue
        lines.append(f'  export {k}="{v}"')
    lines.append(f'  export LLMLOGS_DB="{db}"')
    fwd = " ".join(f'{k}="{v}"' for k, v in forward_proxy_env(port).items())
    lines.append("  # CLIs with no BASE_URL knob: forward-proxy only that command")
    for c in FORWARD_PROXY_CLIS:
        lines.append(f'  {c}() {{ {fwd} command {c} "$@"; }}')
    lines += ["fi", RC_MARK_END]
    return "\n".join(lines) + "\n"


def _rc_fish_block(port: int, db: str) -> str:
    lines = [RC_MARK_START,
             "# Route chatbot CLIs (claude, opencode, …) through the llmlogs proxy when it's up.",
             f'if command -v nc >/dev/null 2>&1; and nc -z 127.0.0.1 {port} 2>/dev/null']
    for k, v in proxy_env(port).items():
        if k in _RC_SKIP:
            continue
        lines.append(f'  set -gx {k} "{v}"')
    lines.append(f'  set -gx LLMLOGS_DB "{db}"')
    fwd = " ".join(f'{k}="{v}"' for k, v in forward_proxy_env(port).items())
    for c in FORWARD_PROXY_CLIS:
        lines.append(f'  function {c}; env {fwd} {c} $argv; end')
    lines += ["end", RC_MARK_END]
    return "\n".join(lines) + "\n"


def _ensure_rc(path: str, block: str) -> str:
    """Append our env block to a shell rc file once (idempotent)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cur = open(path).read() if os.path.exists(path) else ""
    if RC_MARK_START in cur:
        if block in cur:
            return "kept (already installed)"
        _strip_rc(path)  # older block from a previous install → replace it
        cur = open(path).read()
    with open(path, "a") as f:
        if cur and not cur.endswith("\n"):
            f.write("\n")
        f.write(block)
    return "added"


def _strip_rc(path: str) -> str:
    if not os.path.exists(path):
        return "absent"
    lines = open(path).read().splitlines(keepends=True)
    out, skipping, changed = [], False, False
    for ln in lines:
        if RC_MARK_START in ln:
            skipping, changed = True, True
            continue
        if RC_MARK_END in ln:
            skipping = False
            continue
        if not skipping:
            out.append(ln)
    if changed:
        open(path, "w").writelines(out)
        return "removed"
    return "not present"


def _merge_tool_config(path: str, apply) -> str:
    """Merge keys into a JSON tool config, keeping a one-time backup."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        cur = json.load(open(path)) if os.path.exists(path) else {}
    except ValueError:
        bak = path + ".llmlogs.bak"
        os.replace(path, bak)
        cur = {}
        print(f"  {path} was not valid JSON; moved to {bak}")
    else:
        bak = path + ".llmlogs.bak"
        if os.path.exists(path) and not os.path.exists(bak):
            import shutil as _sh
            _sh.copy2(path, bak)
    apply(cur)
    json.dump(cur, open(path, "w"), indent=2)
    return "updated"


def _launchd_plist_content(mitmdump: str, port: int, db: str, upstream: str) -> str:
    log = os.path.join(GLOBAL_DIR, "proxy.log")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{PLIST_LABEL}</string>
<key>ProgramArguments</key><array><string>{mitmdump}</string><string>-s</string><string>{ADDON_PATH}</string><string>--listen-host</string><string>127.0.0.1</string><string>-p</string><string>{port}</string><string>-q</string></array>
<key>EnvironmentVariables</key><dict><key>LLMLOGS_DB</key><string>{db}</string><key>LLMLOGS_PROXY_PORT</key><string>{port}</string><key>LLMLOGS_UPSTREAM</key><string>{upstream}</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>{log}</string><key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"""


def _launchd_uid() -> str:
    import subprocess as _sp
    return str(_sp.run(["id", "-u"], capture_output=True, text=True).stdout.strip())


def _launchd_loaded() -> bool:
    import subprocess as _sp
    r = _sp.run(["launchctl", "print", f"gui/{_launchd_uid()}/{PLIST_LABEL}"],
                capture_output=True)
    return r.returncode == 0


def _launchd_load() -> bool:
    import subprocess as _sp
    uid = _launchd_uid()
    r = _sp.run(["launchctl", "bootstrap", f"gui/{uid}", PLIST_PATH], capture_output=True, text=True)
    if r.returncode != 0:  # already bootstrapped or older macOS → load / kickstart
        _sp.run(["launchctl", "load", "-w", PLIST_PATH], capture_output=True)
    _sp.run(["launchctl", "kickstart", "-k", f"gui/{uid}/{PLIST_LABEL}"],
            capture_output=True)
    return _launchd_loaded()


def _launchd_unload():
    import subprocess as _sp
    uid = _launchd_uid()
    _sp.run(["launchctl", "bootout", f"gui/{uid}/{PLIST_LABEL}"], capture_output=True)
    _sp.run(["launchctl", "unload", "-w", PLIST_PATH], capture_output=True)


def install_global(port: int, db: str, upstream: str,
                   do_launchd: bool = True, do_shell: bool = True,
                   do_configs: bool = True) -> int:
    import subprocess as _sp
    mitmdump = _mitmdump_bin()
    if not mitmdump:
        print("mitmdump not found on PATH; install mitmproxy first (uv sync / pipx install mitmproxy).")
        return 1
    os.makedirs(GLOBAL_DIR, exist_ok=True)
    print(f"[1/4] proxy daemon (port {port}, db {db})")
    if do_launchd:
        if _launchd_loaded():  # pick up changed plist (e.g. new binary/port)
            _launchd_unload()
        open(PLIST_PATH, "w").write(_launchd_plist_content(mitmdump, port, db, upstream))
        print(f"  binary: {mitmdump}")
        ok = _launchd_load() or wait_for_proxy(port)
        print(f"  launchd {PLIST_PATH}: {'running' if ok else 'FAILED — see ~/.llmlogs/proxy.log'}")
    else:
        print("  skipped (--no-launchd)")
    print("[2/4] new terminals (shell rc)")
    if do_shell:
        home = os.path.expanduser("~")
        for rc, kind in [(os.path.join(home, ".zshrc"), "sh"),
                         (os.path.join(home, ".bashrc"), "sh"),
                         (os.path.join(home, ".bash_profile"), "sh"),
                         (os.path.join(home, ".config", "fish", "config.fish"), "fish")]:
            block = _rc_fish_block(port, db) if kind == "fish" else _rc_sh_block(port, db)
            if kind == "fish" and not os.path.exists(rc):
                print(f"  {rc}: skipped (no fish config)")
                continue
            try:
                print(f"  {rc}: {_ensure_rc(rc, block)}")
            except OSError as e:
                print(f"  {rc}: FAILED ({e})")
    else:
        print("  skipped (--no-shell)")
    print("[3/4] GUI apps launched from Finder/Dock (launchctl setenv, until reboot)")
    for k, v in proxy_env(port).items():
        if k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                 "NO_PROXY", "no_proxy", "NODE_USE_ENV_PROXY", "NODE_EXTRA_CA_CERTS"):
            continue
        _sp.run(["launchctl", "setenv", k, v], capture_output=True)
    _sp.run(["launchctl", "setenv", "LLMLOGS_DB", db], capture_output=True)
    print("  set for apps launched from now until reboot.")
    print("  (For persistence across reboots: launch GUI IDEs from a terminal so the")
    print("   shell-rc env applies, or rely on the tool JSON configs written in step 4.)")
    print("[4/4] tool configs (claude settings env, opencode provider baseURL)")
    if do_configs:
        home = os.path.expanduser("~")
        c = os.path.join(home, ".claude", "settings.json")
        try:
            ours = _claude_ours(port)
            print(f"  {c}: " + _merge_tool_config(
                c, lambda d: d.setdefault("env", {}).update(
                    {kp[1]: v for kp, v in ours.items()})))
        except OSError as e:
            print(f"  {c}: FAILED ({e})")
        oj = os.path.join(os.path.expanduser("~"), ".config", "opencode", "opencode.json")

        def _op(d):
            for kp, val in _opencode_ours(port).items():
                _cfg_set(d, kp, val)
        try:
            print(f"  {oj}: " + _merge_tool_config(oj, _op))
        except OSError as e:
            print(f"  {oj}: FAILED ({e})")
    else:
        print("  skipped (--no-config)")
    try:
        json.dump({"port": port, "db": db, "upstream": upstream},
                  open(INSTALL_RECEIPT, "w"), indent=2)
    except OSError:
        pass
    print("\nDone. Open a NEW terminal (old ones: run `exec zsh`) and use any CLI —\n"
          "it is captured automatically. GUI IDEs: relaunch them (or launch from a\n"
          "terminal) to pick up the env. Check: `python capture.py status`.")
    return 0


def uninstall_global() -> int:
    import subprocess as _sp
    port = 8080
    try:
        port = int(json.load(open(INSTALL_RECEIPT)).get("port", port))
    except (OSError, ValueError):
        pass
    print("reverting tool configs to pre-install state…")
    home = os.path.expanduser("~")
    for path, ours in ((os.path.join(home, ".claude", "settings.json"), _claude_ours(port)),
                       (os.path.join(home, ".config", "opencode", "opencode.json"),
                        _opencode_ours(port))):
        try:
            print(f"  {path}: {_revert_tool_config(path, ours)}")
        except OSError as e:
            print(f"  {path}: FAILED ({e})")
    print("removing launchd daemon…")
    _launchd_unload()
    try:
        os.remove(PLIST_PATH)
        print(f"  removed {PLIST_PATH}")
    except FileNotFoundError:
        print("  plist already gone")
    except OSError as e:
        print(f"  FAILED ({e})")
    home = os.path.expanduser("~")
    for rc in [os.path.join(home, ".zshrc"), os.path.join(home, ".bashrc"),
               os.path.join(home, ".bash_profile"),
               os.path.join(home, ".config", "fish", "config.fish")]:
        try:
            print(f"  {rc}: {_strip_rc(rc)}")
        except OSError as e:
            print(f"  {rc}: FAILED ({e})")
    for k in list(proxy_env(8080)) + ["LLMLOGS_DB"]:
        _sp.run(["launchctl", "unsetenv", k], capture_output=True)
    print("launchctl env cleared.")
    stop_proxy()
    print("Done. Your current shell may still have the old proxy vars — either open a\n"
          "NEW terminal or run:\n"
          "  unset ANTHROPIC_BASE_URL ANTHROPIC_API_URL OPENAI_BASE_URL OPENAI_API_BASE \\\n"
          "    OPENROUTER_BASE_URL GEMINI_API_URL GOOGLE_GEMINI_BASE_URL LLMLOGS_DB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
