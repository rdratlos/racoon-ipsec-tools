#!/usr/bin/env python3
"""Minimal mock of an internal model router (RFC 0005 Phase 3 research).

Serves two wire formats on one port:

  POST /v1/chat/completions   OpenAI-compatible (used by OpenCode)
  POST /v1/messages           Anthropic Messages (used by Claude Code via
                              ANTHROPIC_BASE_URL)
  GET  /v1/models             model list (both formats)

Every response
  - reports the router alias (default "KITCH-Coder") in the body `model`
    field, whatever model the client requested;
  - names the deployment that "actually" answered in LiteLLM's response
    headers (litellm 1.106.1, litellm/proxy/common_request_processing.py,
    get_custom_headers(): x-litellm-model-id, x-litellm-model-name,
    x-litellm-model-api-base; litellm/router.py: x-litellm-model-group);
  - switches deployment every --switch-every requests (round robin).

The mock is not a language model. Its reply text quotes the lines of the
system prompt that mention a model, so the experiment shows what a real
model *could* have known about its own identity. If the client offers a
Bash/shell tool and the conversation has no tool result yet, the first
reply is a tool call (--probe-command, default `echo provenance-probe`),
so tool hooks fire.

Each request is appended as one JSON line to --log (requested model,
streaming flag, deployment, response model), so the log shows ground truth.

Usage: router_mock.py [--port 8787] [--alias KITCH-Coder] [--switch-every 2]
                      [--log router.jsonl]
Stdlib only. Bind address is 127.0.0.1; do not expose it.
"""
import argparse
import itertools
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEPLOYMENTS = [
    {"id": "deploy-a-7f3c", "name": "hosted_vllm/qwen3-coder-480b-a35b-fp8",
     "api_base": "http://gpu-pool-a.internal:8000/v1"},
    {"id": "deploy-b-91e2", "name": "hosted_vllm/kitch-coder-2026-09-int4",
     "api_base": "http://gpu-pool-b.internal:8000/v1"},
]


class State:
    def __init__(self, alias, switch_every, log_path,
                 probe="echo provenance-probe"):
        self.alias = alias
        self.probe = probe
        self.switch_every = max(1, switch_every)
        self.log_path = log_path
        self.counter = itertools.count()
        self.lock = threading.Lock()

    def next_deployment(self):
        with self.lock:
            n = next(self.counter)
        return n, DEPLOYMENTS[(n // self.switch_every) % len(DEPLOYMENTS)]

    def log(self, entry):
        with self.lock, open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(c.get("text", "") for c in content
                         if isinstance(c, dict) and c.get("type") == "text")
    return ""


def identity_lines(system_text):
    """System-prompt lines that tell the model what it is."""
    pat = re.compile(r"powered by|model id|model named|you are (?:claude|a |an )"
                     r"|running on|opencode", re.I)
    lines = [ln.strip() for ln in system_text.splitlines() if pat.search(ln)]
    return [ln[:240] for ln in lines if ln][:12]


def reply_text(system_text, deployment, alias):
    lines = identity_lines(system_text)
    told = "; ".join(lines) if lines else "(nothing about my model)"
    return (f"[router-mock] I cannot know which deployment answered. "
            f"The harness told me: {told}")


class Handler(BaseHTTPRequestHandler):
    server_version = "router-mock/1"
    state: State = None  # set in main()

    def log_message(self, fmt, *args):  # quiet
        pass

    def _send_json(self, code, obj, headers):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _start_sse(self, headers):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()

    def _sse(self, data, event=None):
        chunk = ""
        if event:
            chunk += f"event: {event}\n"
        chunk += f"data: {data if isinstance(data, str) else json.dumps(data)}\n\n"
        self.wfile.write(chunk.encode())
        self.wfile.flush()

    def _router_headers(self, dep):
        return {
            "x-litellm-model-id": dep["id"],
            "x-litellm-model-name": dep["name"],
            "x-litellm-model-api-base": dep["api_base"],
            "x-litellm-model-group": self.state.alias,
        }

    def do_GET(self):
        if self.path.rstrip("/").endswith("/v1/models"):
            now = int(time.time())
            self._send_json(200, {
                "object": "list",
                "data": [{"id": self.state.alias, "object": "model",
                          "created": now, "owned_by": "router",
                          "type": "model", "display_name": self.state.alias,
                          "created_at": "2026-01-01T00:00:00Z"}],
                "has_more": False, "first_id": self.state.alias,
                "last_id": self.state.alias}, {})
        else:
            self._send_json(404, {"error": "not found"}, {})

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = {}
        path = self.path.split("?")[0]
        if path.endswith("/v1/messages/count_tokens"):
            self._send_json(200, {"input_tokens": 100}, {})
            return
        n, dep = self.next_deployment_logged(req, path)
        if path.endswith("/v1/chat/completions"):
            self.openai(req, dep)
        elif path.endswith("/v1/messages"):
            self.anthropic(req, dep)
        else:
            self._send_json(404, {"error": "not found"}, {})

    def next_deployment_logged(self, req, path):
        n, dep = self.state.next_deployment()
        if path.endswith("/v1/messages"):
            system = _text_of(req.get("system", ""))
        else:
            system = "\n".join(_text_of(m.get("content"))
                               for m in req.get("messages", [])
                               if m.get("role") in ("system", "developer"))
        self.state.log({
            "n": n, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "path": path, "requested_model": req.get("model"),
            "stream": bool(req.get("stream")),
            "deployment": dep["id"], "deployment_model": dep["name"],
            "response_model": self.state.alias,
            "system_identity_lines": identity_lines(system),
            "client_headers": {k: v for k, v in self.headers.items()
                               if k.lower() in ("user-agent", "x-app",
                                                "anthropic-version",
                                                "x-stainless-package-version")},
        })
        return n, dep

    # -- OpenAI chat completions -------------------------------------------
    def openai(self, req, dep):
        msgs = req.get("messages", [])
        system = "\n".join(_text_of(m.get("content")) for m in msgs
                           if m.get("role") in ("system", "developer"))
        tools = [t.get("function", {}).get("name", "") for t in req.get("tools", [])]
        has_result = any(m.get("role") == "tool" for m in msgs)
        shell = next((t for t in tools if t.lower() in ("bash", "shell")), None)
        alias = self.state.alias
        rid = "chatcmpl-" + uuid.uuid4().hex[:12]
        created = int(time.time())
        headers = self._router_headers(dep)
        if shell and not has_result:
            call = {"id": "call_" + uuid.uuid4().hex[:8], "type": "function",
                    "function": {"name": shell, "arguments": json.dumps(
                        {"command": self.state.probe,
                         "description": "probe"})}}
            message, finish = {"role": "assistant", "content": None,
                               "tool_calls": [call]}, "tool_calls"
        else:
            message = {"role": "assistant",
                       "content": reply_text(system, dep, alias)}
            finish = "stop"
        usage = {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
        if not req.get("stream"):
            self._send_json(200, {"id": rid, "object": "chat.completion",
                                  "created": created, "model": alias,
                                  "choices": [{"index": 0, "message": message,
                                               "finish_reason": finish}],
                                  "usage": usage}, headers)
            return
        self._start_sse(headers)
        base = {"id": rid, "object": "chat.completion.chunk",
                "created": created, "model": alias}
        if message.get("tool_calls"):
            tc = dict(message["tool_calls"][0], index=0)
            delta = {"role": "assistant", "content": None, "tool_calls": [tc]}
        else:
            delta = {"role": "assistant", "content": message["content"]}
        self._sse(dict(base, choices=[{"index": 0, "delta": delta,
                                       "finish_reason": None}]))
        self._sse(dict(base, choices=[{"index": 0, "delta": {},
                                       "finish_reason": finish}],
                       usage=usage))
        self._sse("[DONE]")

    # -- Anthropic Messages -------------------------------------------------
    def anthropic(self, req, dep):
        system = _text_of(req.get("system", ""))
        msgs = req.get("messages", [])
        tools = [t.get("name", "") for t in req.get("tools", [])]
        has_result = any(isinstance(m.get("content"), list) and any(
            isinstance(c, dict) and c.get("type") == "tool_result"
            for c in m["content"]) for m in msgs)
        alias = self.state.alias
        mid = "msg_mock" + uuid.uuid4().hex[:16]
        headers = self._router_headers(dep)
        if "Bash" in tools and not has_result and len(msgs) <= 2 and \
                "provenance-probe" not in json.dumps(msgs):
            block = {"type": "tool_use", "id": "toolu_" + uuid.uuid4().hex[:12],
                     "name": "Bash", "input": {"command": self.state.probe,
                                               "description": "probe"}}
            stop = "tool_use"
        else:
            block = {"type": "text", "text": reply_text(system, dep, alias)}
            stop = "end_turn"
        usage = {"input_tokens": 100, "output_tokens": 20,
                 "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
        msg = {"id": mid, "type": "message", "role": "assistant",
               "model": alias, "content": [block], "stop_reason": stop,
               "stop_sequence": None, "usage": usage}
        if not req.get("stream"):
            self._send_json(200, msg, headers)
            return
        self._start_sse(headers)
        start = dict(msg, content=[], stop_reason=None,
                     usage=dict(usage, output_tokens=1))
        self._sse({"type": "message_start", "message": start}, "message_start")
        if block["type"] == "text":
            self._sse({"type": "content_block_start", "index": 0,
                       "content_block": {"type": "text", "text": ""}},
                      "content_block_start")
            self._sse({"type": "content_block_delta", "index": 0,
                       "delta": {"type": "text_delta", "text": block["text"]}},
                      "content_block_delta")
        else:
            self._sse({"type": "content_block_start", "index": 0,
                       "content_block": dict(block, input={})},
                      "content_block_start")
            self._sse({"type": "content_block_delta", "index": 0,
                       "delta": {"type": "input_json_delta",
                                 "partial_json": json.dumps(block["input"])}},
                      "content_block_delta")
        self._sse({"type": "content_block_stop", "index": 0}, "content_block_stop")
        self._sse({"type": "message_delta",
                   "delta": {"stop_reason": stop, "stop_sequence": None},
                   "usage": {"output_tokens": 20}}, "message_delta")
        self._sse({"type": "message_stop"}, "message_stop")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--alias", default="KITCH-Coder")
    ap.add_argument("--switch-every", type=int, default=2)
    ap.add_argument("--log", default="router.jsonl")
    ap.add_argument("--probe-command", default="echo provenance-probe",
                    help="shell command of the one tool call the mock makes")
    args = ap.parse_args()
    Handler.state = State(args.alias, args.switch_every, args.log,
                          args.probe_command)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"router-mock on http://127.0.0.1:{args.port} alias={args.alias} "
          f"switch-every={args.switch_every} log={args.log}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
