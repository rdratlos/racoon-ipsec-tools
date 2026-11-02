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
   "call_id", "status", "endpoint"}
"endpoint" is the origin (scheme://host[:port]) the upstream hop finally
reached -- what we observed, not what was configured (an env proxy may
rewrite it). It stays absent when the connection failed or the proxy ran
an older version; declare then records no endpoints, never a guess.

Deployment headers recognised (LiteLLM-style names, RFC 0005 Q4):
  x-litellm-model-id, x-litellm-model-name, x-litellm-deployment,
  x-litellm-call-id, x-routify-call-id. Unknown x-*response-model/-deployment
  headers are logged too. Stdlib only.
"""

import argparse
import datetime
import http.client
import json
import re
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEPLOYMENT_RE = re.compile(r"^(x-[\w-]*(model|deployment|call)[\w-]*)$", re.I)
# some routers report the serving deployment in the JSON body instead of
# headers (observed: KITCH adds "router_model_name" alongside the stable
# alias in "model")
BODY_DEPLOYMENT_RE = re.compile(r"^[\w.-]*(router|deployment)[\w.-]*$", re.I)
# our own correlation id: the x-* shape is reserved for what a gateway
# reported, so a value we made up must never have it (see _proxy)
OWN_CALL_ID_HEADER = "provcap-call-id"
OWN_CALL_ID_KEY = "proxy_call_id"
BODY_SCAN_LIMIT = 1 << 20
MAX_LOGGED_HEADERS = 100
PROXY_HEADERS = {"host", "connection", "content-length", "accept-encoding"}
# this server speaks HTTP/1.0 (Handler.protocol_version), so every response
# it sends is terminated by the close of the connection. The upstream's own
# framing must not be copied to the client: a copied framing is a promise
# the proxy cannot keep (observed: a plain client hung on both a chunked
# stream and a Content-Length response), and a framing header we claim to
# offer but cannot honour is worse than none. An HTTP/1.1 client that reads
# until the close sees exactly the bytes we copied: RFC 7230 3.3.3/3.3.4
# (a response with no framing ends at the server's close), and "Connection:
# close", which send_response() adds for a 1.0 server, tells it the close
# is coming (RFC 9112 6.1). Copying the upstream's framing instead, or
# claiming a framing we do not send, tells the client it may stop early:
# observed on this code, an HTTP/1.1 client saw "Content-Length: 0" and
# discarded the body while the capture recorded it as served
RESPONSE_DROP = frozenset({"transfer-encoding", "connection", "content-length",
                           "server", "date"})

lock = threading.Lock()

# Honour the environment proxy for the upstream hop (an internal endpoint
# may only be reachable through it); localhost is never proxied, so the
# client -> proxy hop cannot loop. TLS verification stays ON by default;
# --insecure documents an unverified capture hop.
#
# The environment is read per request, not once at import: ProxyHandler
# reads it in its constructor and caches it for its whole life, so an
# opener built at startup would keep whatever environment existed then.
# A harness that exported http_proxy after startup would otherwise have
# its localhost hop sent to the web proxy (observed: no_proxy lists that
# carry loopback only as a CIDR like "127.0.0.0/8", which ProxyHandler
# does not expand; Squid then answers an error page for our own listener).
# localhost is exempted from the hop whatever the environment says, which
# also rules out a loop through our own listener.
LOCAL_NO_PROXY = ("localhost", "127.0.0.1", "::1")


def _proxy_bypass(host):
    return any(host == h or host.endswith("." + h) for h in LOCAL_NO_PROXY)


class _EnvProxyHandler(urllib.request.ProxyHandler):
    """The environment's proxies, with localhost always bypassed. The
    default proxy_open() consults the no_proxy list built in the
    constructor; bypassing before it keeps localhost direct whatever that
    list says, and returning None routes the request with no proxy."""

    def proxy_open(self, req, key, proxy):
        if _proxy_bypass(req.host.split(":")[0].lower()):
            return None
        return super().proxy_open(req, key, proxy)


def _build_opener(insecure=False):
    ctx = ssl._create_unverified_context() if insecure else None
    # proxies=None: ProxyHandler reads the environment when built, which
    # happens per request, so an export after startup is seen (see above)
    return urllib.request.build_opener(
        _EnvProxyHandler(),
        urllib.request.HTTPSHandler(context=ctx))


def _origin(url):
    """scheme://host[:port] of a URL, or None if unparseable."""
    try:
        u = urllib.parse.urlsplit(url)
        if not u.scheme or not u.netloc:
            return None
        return f"{u.scheme}://{u.netloc}"
    except ValueError:
        return None


def _hop_headers(headers):
    """Headers of one hop, as the upstream sent them. The capture evidence
    is this list, so the number of names written into a log entry is bounded
    (an upstream must not be able to grow the record without limit)."""
    out = {}
    for i, (k, v) in enumerate(headers.items()):
        if i >= MAX_LOGGED_HEADERS:
            break
        out[k.lower()] = v
    return out


class Handler(BaseHTTPRequestHandler):
    upstream = ""
    log_path = ""
    log_bodies = False
    insecure = False
    # 1.0 on purpose: every response we serve is terminated by the close of
    # the connection, so no framing header of the upstream is ever needed
    # or honest to copy (RESPONSE_DROP). HTTP/1.0 clients read to the close
    # by definition; an HTTP/1.1 client is told "Connection: close" by
    # send_response() and then reads to the close too (see RESPONSE_DROP)
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):  # quiet; our own log is the record
        pass

    def _forward(self, resp, scan_limit=BODY_SCAN_LIMIT, skip_headers=False):
        """Copy the upstream response to the client as it arrives: the first
        byte goes out before the body is complete, so a streamed (SSE)
        completion keeps streaming under capture. A buffered proxy would
        change the behaviour it is supposed to observe (RFC 0005 §7), and a
        harness that hangs waiting for a first event is a capture we lose
        entirely. The identity scan stops at `scan_limit` bytes, so
        observation costs bounded memory and never delays the client beyond
        that point. The entry is written when the copy ends: a truncated
        capture then carries the bytes seen so far, never a claim of more.

        `resp` may be a failed-status response (`urllib.error.HTTPError`,
        which is also a response object): an upstream error is evidence
        too, so its body is copied and scanned like any other. `status` is
        read before the copy because a body cut short can raise, and the
        entry must still say which response was served."""
        status = getattr(resp, "status", None)
        if status is None:
            status = resp.getcode()
        headers = _hop_headers(resp.headers)
        if 100 <= status < 200 and status != 101:
            # an interim response (100-continue) is not the answer: it
            # carries no body (RFC 7231 6.2.1) and would be swallowed in
            # the client, so the capture records the final response. This
            # hop does not speak 100-continue to the client (our _proxy
            # reads the whole body up front and forwards it, and
            # BaseHTTPRequestHandler does not read Expect: 100-continue
            # itself), and a proxy that does not forward the interim does
            # not forward its hop-by-hop Connection header either
            self._forward(resp, 0, skip_headers=True)
            # the interim is fully consumed and the final response's
            # status and headers are read (isFinal() above drove that);
            # self.forwarded counts only the body that reached the client,
            # so it stays zero for the interim here
            status = resp.status
            headers = _hop_headers(resp.headers)
        if not skip_headers:
            self.send_response(status)
            for k, v in resp.headers.items():
                if k.lower() in RESPONSE_DROP:
                    continue
                self.send_header(k, v)
        self.end_headers()
        scanned = bytearray()
        while True:
            try:
                # read1, not read: read(n) tries to fill n, so it blocks
                # until the whole body arrives and the first event of an SSE
                # stream sits in the buffer until the stream ends, which is
                # the buffering this copy exists to avoid (see the docstring).
                # read1 returns what is already buffered and blocks only when
                # nothing has arrived, so an event goes out as the upstream
                # sends it. At the end of the body it returns b'' (never
                # None), so the loop below still terminates.
                chunk = resp.read1(65536)
            except (OSError, http.client.HTTPException) as e:
                # the upstream hop broke: OSError for a socket failure,
                # http.client.HTTPException (IncompleteRead: it ended
                # before its framing said the body was over) for a stream
                # cut mid chunk. The client has received what it received,
                # and there is nothing left to forward
                self.aborted = "upstream: " + (str(e) or e.__class__.__name__)
                break
            if not chunk:
                break
            if len(scanned) < scan_limit:
                scanned += chunk[:scan_limit - len(scanned)]
            try:
                self.wfile.write(chunk)
                self.wfile.flush()
            except OSError as e:
                # the client hung up (a stream it no longer wants): the
                # exception propagates to _proxy, where the request is
                # recorded with what was forwarded before the break
                self.aborted = str(e) or e.__class__.__name__
                raise
            self.forwarded += len(chunk)
        return status, headers, bytes(scanned)

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
        headers[OWN_CALL_ID_HEADER] = call_id
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method=method)
        entry = {
            "at": datetime.datetime.now(datetime.timezone.utc)
                  .isoformat(timespec="seconds").replace("+00:00", "Z"),
            "path": self.path,
            "requested": requested,
            "response_model": None,
            "deployments": {},
            OWN_CALL_ID_KEY: call_id,
            "status": None,
            "endpoint": None,
        }
        # self.forwarded and self.aborted belong to the copy in _forward();
        # initialised here so the handlers below can read them when the
        # open failed and no copy ever happened
        self.forwarded = 0
        self.aborted = None
        forwarded = 0
        try:
            with _build_opener(self.insecure).open(req) as resp:
                status, hop_headers, scanned = self._forward(resp)
                forwarded = self.forwarded
                entry["status"] = status
                entry["endpoint"] = _origin(resp.geturl() or url)
                entry["deployments"] = {
                    k: v for k, v in hop_headers.items() if DEPLOYMENT_RE.match(k)}
                if self.log_bodies:
                    entry["response_body_truncated"] = \
                        scanned[:4096].decode("utf-8", "replace")
                else:
                    entry["response_model"], body_dep = _response_model(scanned)
                    entry["deployments"].update(body_dep)
        except urllib.error.HTTPError as e:
            status, hop_headers, scanned = self._forward(e, 4096)
            forwarded = self.forwarded
            entry["status"] = status
            entry["endpoint"] = _origin(e.url or url)
            entry["deployments"] = {
                k: v for k, v in hop_headers.items() if DEPLOYMENT_RE.match(k)}
            if not self.log_bodies:
                entry["response_model"], body_dep = _response_model(scanned)
                entry["deployments"].update(body_dep)
        except OSError as e:
            if self.forwarded:
                # the client broke the copy (a stream that starts is a
                # stream the client may end early): what arrived before
                # the break is still evidence, and the record says so.
                # Nothing is sent to the client: the response already
                # started, and the socket that broke is the one we would
                # write the error to
                self._record(entry, self.forwarded, self.aborted
                             or str(e) or e.__class__.__name__)
                return
            entry["status"] = "proxy-error"
            entry["error"] = str(e)
            # the response cannot be proxied; send_error answers the
            # request itself and ends this connection
            self.send_error(502, f"upstream failed: {e}")
        self._record(entry, forwarded, self.aborted)

    def _record(self, entry, forwarded, aborted):
        # every proxied request is recorded, including one that reached the
        # client with zero bytes (a 502, a 204, a stream cut before its
        # first chunk): a failed request is evidence too, and dropping it
        # would leave the log claiming fewer requests than the harness made
        # (principle 12). read_capture() ignores an entry that carries
        # nothing to say; it still counts toward what the log holds
        entry["bytes"] = forwarded
        if aborted:
            # the copy stopped early: the record holds what was seen,
            # and says so rather than claiming a complete response
            entry["abort"] = aborted
        # the entry is always offered to _write_entry: deciding whether
        # it goes anywhere is that hook's job, so a test sink that
        # does not use log_path still receives it
        self._write_entry(entry)

    def _write_entry(self, entry):
        # append under the module lock: concurrent calls each land on one
        # line; a test that wants the entries of one server installs its
        # own Handler subclass and overrides this
        if not self.log_path:
            return
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
    Handler.insecure = args.insecure
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
