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
  python3 tools/provcap-proxy.py --listen localhost:8787 \
      --upstream https://router.example.org/v1 --log capture.jsonl
  # then point the harness at http://localhost:8787/v1

Point the harness at "localhost", not "127.0.0.1": corporate no_proxy
lists typically contain "localhost" verbatim but only CIDR-style loopback
("127.0.0.0/8"), which many env-proxy matchers do not expand -- the
harness would then send us to the web proxy (Squid answers 503/403 for
loopback targets). "localhost" matches in both string- and CIDR-aware
matchers.

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
import ssl
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEPLOYMENT_RE = re.compile(r"^(x-[\w-]*(model|deployment|call)[\w-]*)$", re.I)
# some routers report the serving deployment in the JSON body instead of
# headers (observed: KITCH adds "router_model_name" alongside the stable
# alias in "model")
BODY_DEPLOYMENT_RE = re.compile(r"^[\w.-]*(router|deployment)[\w.-]*$", re.I)
CALL_ID_HEADERS = ("x-litellm-call-id", "x-routify-call-id", "x-request-id")
PROXY_HEADERS = {"host", "connection", "content-length", "accept-encoding"}

lock = threading.Lock()

# Honour the environment proxy for the upstream hop (an internal endpoint
# may only be reachable through it); 127.0.0.1 is never proxied, so the
# client -> proxy hop cannot loop. TLS verification stays ON by default;
# --insecure documents an unverified capture hop.
_opener = urllib.request.build_opener(urllib.request.HTTPSHandler())


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
            with _opener.open(req) as resp:
                resp_body = resp.read()
                entry["status"] = resp.status
                for k, v in resp.headers.items():
                    if DEPLOYMENT_RE.match(k):
                        entry["deployments"][k.lower()] = v
                if self.log_bodies:
                    entry["response_body_truncated"] = \
                        resp_body[:4096].decode("utf-8", "replace")
                else:
                    entry["response_model"], body_dep = _response_model(resp_body)
                    entry["deployments"].update(body_dep)
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
    """Return (model, deployments) as reported in the response body."""
    deployments = {}
    if not body:
        return None, deployments
    if body[:1] == b"{":
        try:
            doc = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, deployments
        for k, v in doc.items():
            if BODY_DEPLOYMENT_RE.match(k) and isinstance(v, str) \
                    and k != "model":
                deployments["body:" + k] = v
        return doc.get("model"), deployments
    # SSE stream: the model appears on each data: line; take the first.
    for line in body.split(b"\n"):
        line = line.strip()
        if line.startswith(b"data:") and b"{" in line:
            try:
                doc = json.loads(line[5:].strip())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            for k, v in doc.items():
                if BODY_DEPLOYMENT_RE.match(k) and isinstance(v, str) \
                        and k != "model":
                    deployments["body:" + k] = v
            return doc.get("model"), deployments
    return None, deployments


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--listen", default="localhost:8787",
                    help='host:port; keep "localhost" unless you know your '
                         "clients' no_proxy handles it (see module docstring)")
    ap.add_argument("--upstream", required=True,
                    help="base URL to forward to, e.g. https://api.example/v1")
    ap.add_argument("--log", default="provcap.jsonl")
    ap.add_argument("--log-bodies", action="store_true",
                    help="log truncated response bodies instead of parsing "
                         "the model field (contains prompt echoes; off by default)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip upstream TLS verification (untrusted internal "
                         "CA; the capture hop then proves nothing about the "
                         "endpoint's identity)")
    args = ap.parse_args(argv)
    host, _, port = args.listen.partition(":")
    Handler.upstream = args.upstream
    Handler.log_path = args.log
    Handler.log_bodies = args.log_bodies
    global _opener
    if args.insecure:
        ctx = ssl._create_unverified_context()
        _opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx))
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
