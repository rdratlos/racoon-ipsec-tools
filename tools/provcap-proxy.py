#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2026 Thomas Reim and the racoon-ipsec-tools contributors

"""provcap-proxy: local capture proxy for AI provenance (RFC 0005 Phase 3).

A pass-through HTTP proxy between a harness (OpenCode, Claude Code, ...) and
the provider or router it talks to. It changes nothing on the wire except an
added call id header; it logs, per request, what the harness asked for, what
the response body claims answered, and the router's deployment headers.
That log is the strongest evidence a contributor can collect without an
upstream change: `prov declare --evidence capture-log:FILE` turns it into
model_reported_by = api (plain provider) or router (deployment headers seen).

Usage:
  python3 tools/provcap-proxy.py --listen 127.0.0.1:8787 \
      --upstream https://router.example.org/v1 --log capture.jsonl
  # then point the harness at http://127.0.0.1:8787/v1

Log format: JSON lines, one object per completion request:
  {"at", "path", "requested", "response_model", "deployments": {...},
   "call_id", "status"}

Deployment headers recognised (LiteLLM-style names, RFC 0005 Q4):
  x-litellm-model-id, x-litellm-model-name, x-litellm-deployment,
  x-litellm-call-id, x-routify-call-id. Unknown x-*response-model/-deployment
  headers are logged too. Stdlib only.
"""

import argparse
import datetime
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEPLOYMENT_RE = re.compile(r"^(x-[\w-]*(model|deployment|call)[\w-]*)$", re.I)
CALL_ID_HEADERS = ("x-litellm-call-id", "x-routify-call-id", "x-request-id")
PROXY_HEADERS = {"host", "connection", "content-length", "accept-encoding"}

lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    upstream = ""
    log_path = ""
    log_bodies = False

    def log_message(self, fmt, *args):  # quiet; our own log is the record
        pass

    def _proxy(self, method):
        up = self.upstream.rstrip("/")
        url = up + self.path
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else None

        req_body = None
        requested = None
        if body:
            try:
                req_body = json.loads(body)
                requested = req_body.get("model")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in PROXY_HEADERS}
        call_id = "prov-" + datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y%m%d%H%M%S%f")
        headers["x-routify-call-id"] = call_id
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method=method)
        entry = {
            "at": datetime.datetime.now(datetime.timezone.utc)
                  .isoformat(timespec="seconds").replace("+00:00", "Z"),
            "path": self.path,
            "requested": requested,
            "response_model": None,
            "deployments": {},
            "call_id": call_id,
            "status": None,
        }
        try:
            with urllib.request.urlopen(req) as resp:
                resp_body = resp.read()
                entry["status"] = resp.status
                for k, v in resp.headers.items():
                    if DEPLOYMENT_RE.match(k):
                        entry["deployments"][k.lower()] = v
                if self.log_bodies:
                    entry["response_body_truncated"] = \
                        resp_body[:4096].decode("utf-8", "replace")
                else:
                    entry["response_model"] = _response_model(resp_body)
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            resp_body = e.read()
            entry["status"] = e.code
            for k, v in e.headers.items():
                if DEPLOYMENT_RE.match(k):
                    entry["deployments"][k.lower()] = v
            self.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp_body)
        except OSError as e:
            entry["status"] = "proxy-error"
            entry["error"] = str(e)
            self.send_error(502, f"upstream failed: {e}")
        if self.log_path:
            with lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")

    def do_POST(self):
        self._proxy("POST")

    def do_GET(self):
        self._proxy("GET")


def _response_model(body):
    if not body:
        return None
    if body[:1] == b"{":
        try:
            return json.loads(body).get("model")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
    # SSE stream: the model appears on each data: line; take the first.
    for line in body.split(b"\n"):
        line = line.strip()
        if line.startswith(b"data:") and b"{" in line:
            try:
                return json.loads(line[5:].strip()).get("model")
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--listen", default="127.0.0.1:8787")
    ap.add_argument("--upstream", required=True,
                    help="base URL to forward to, e.g. https://api.example/v1")
    ap.add_argument("--log", default="provcap.jsonl")
    ap.add_argument("--log-bodies", action="store_true",
                    help="log truncated response bodies instead of parsing "
                         "the model field (contains prompt echoes; off by default)")
    args = ap.parse_args(argv)
    host, _, port = args.listen.partition(":")
    Handler.upstream = args.upstream
    Handler.log_path = args.log
    Handler.log_bodies = args.log_bodies
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    print(f"provcap-proxy: http://{host}:{port} -> {args.upstream}, "
          f"log {args.log}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
