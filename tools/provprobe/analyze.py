import argparse, glob, importlib.util, json, os, re, sys

ap = argparse.ArgumentParser()
for a in ("work", "model", "prov", "family", "profile", "harness", "disclosure", "base"):
    ap.add_argument("--" + a, default="")
ap.add_argument("--n", type=int, default=6)
a = ap.parse_args()

spec = importlib.util.spec_from_file_location("prov", a.prov)
prov = importlib.util.module_from_spec(spec); spec.loader.exec_module(prov)

def rd(name, mode="r"):
    try:
        with open(os.path.join(a.work, name), mode, errors="replace") as f:
            return f.read()
    except OSError:
        return ""

def headers(name):
    blocks = [b for b in re.split(r"\r?\n\r?\n", rd(name).strip()) if b.strip()]
    if not blocks:
        return None, {}
    lines = blocks[-1].splitlines()
    m = re.match(r"HTTP/\S+\s+(\d+)", lines[0])
    h = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1); h[k.strip().lower()] = v.strip()
    return (int(m.group(1)) if m else None), h

def jbody(name):
    try:
        return json.loads(rd(name))
    except ValueError:
        return None

findings, asks = [], []
def F(level, msg): findings.append((level, msg))

# --- non-streaming probes
plain = []
for i in range(1, a.n + 1):
    st, h = headers(f"plain_{i}.hdr"); b = jbody(f"plain_{i}.body")
    plain.append((st, h, b))
ok = [p for p in plain if p[0] == 200 and isinstance(p[2], dict)]
F("OK" if len(ok) == a.n else "WARN", f"{len(ok)}/{a.n} non-streaming completions answered 200 with a JSON body")
models = sorted({str(p[2].get("model")) for p in ok if p[2].get("model")})
echo = [m for m in models if m.casefold() == a.model.casefold()]
if not models:
    F("WARN", "response body carries no 'model' field: nothing in the body to record")
elif echo:
    F("WARN", f"response model {models} echoes the requested alias: a route label, not evidence of what ran (principle 8)")
else:
    F("OK", f"response model differs from the alias: {models}")
if len(models) > 1:
    F("WARN", f"{len(models)} distinct response models in {len(ok)} identical requests: the answering model changes behind the alias")

# --- all response header names (discovery; the proxy only logs x-*model/deployment/call)
names = {}
for _, h, _b in plain:
    for k in h: names[k] = names.get(k, 0) + 1
interesting = sorted(k for k in names if re.search(r"model|deploy|route|backend|provider|region|request-id|call-id|upstream|via|served|version", k))
F("OK" if interesting else "WARN", "response headers that may identify the backend: " + (", ".join(interesting) or "none seen"))
varying = []
for k in interesting:
    vals = {p[1].get(k) for p in plain if p[1].get(k)}
    if len(vals) > 1: varying.append(k)
if varying:
    F("WARN", "these headers vary between identical requests (deployment switch or request ids): " + ", ".join(varying))

# --- capture log through the same reader declare uses
ev = None; trust = None
try:
    ev = prov.read_capture(os.path.join(a.work, "capture.jsonl"))
    trust = prov.evidence_trust(ev)
except Exception as e:                                   # noqa: BLE001
    F("FAIL", f"capture log unreadable by prov.read_capture: {e}")
if ev:
    cap = ev["capture"]
    F("OK", f"capture proxy recorded {cap['requests']} completion request(s), endpoints {cap.get('endpoints', 'none recorded')}")
    depl = sorted({o.get("deployment") for o in ev["observations"] if o.get("deployment")})
    F("OK" if trust else "WARN", f"prov.py would record model_reported_by = {trust or 'nothing (no usable evidence)'}; deployments seen: {depl or 'none'}")

# --- streaming
sids = set(); sse_ok = 0
for i in (1, 2):
    st, h = headers(f"stream_{i}.hdr"); body = rd(f"stream_{i}.body")
    ev_lines = [l[5:].strip() for l in body.splitlines() if l.startswith("data:")]
    ms = set()
    for l in ev_lines:
        if l and l != "[DONE]":
            try: ms.add(json.loads(l).get("model"))
            except ValueError: pass
    if st == 200 and ev_lines: sse_ok += 1
    sids |= {m for m in ms if m}
F("OK" if sse_ok == 2 else "WARN", f"streaming: {sse_ok}/2 requests delivered SSE events; model in stream chunks: {sorted(sids) or 'none'}")
if sids and models and not (sids <= set(models)):
    F("WARN", "streamed model id differs from the non-streaming one")

# --- tools, usage, model list
b = jbody("tools_1.body"); tc = False
if isinstance(b, dict):
    ch = (b.get("choices") or [{}])[0]
    tc = bool((ch.get("message") or {}).get("tool_calls")) or ch.get("finish_reason") == "tool_calls"
F("OK" if tc else "WARN", "tool calling (needed by an agent harness): " + ("works" if tc else "no tool call returned"))
F("OK" if any(isinstance(p[2], dict) and p[2].get("usage") for p in ok) else "WARN",
  "usage block in responses: " + ("present" if any(isinstance(p[2], dict) and p[2].get("usage") for p in ok) else "absent"))
mb = jbody("models.body"); ids = []
if isinstance(mb, dict) and isinstance(mb.get("data"), list):
    ids = [m.get("id") for m in mb["data"] if isinstance(m, dict)]
F("OK" if ids else "WARN", f"model list: {len(ids)} id(s)" + (f", alias {'listed' if a.model in ids else 'NOT listed'}" if ids else ""))

# --- recommendation (never invents a family, never claims more than the evidence)
fam = a.family or "FAMILY-TBD"
if trust == "api" and models and not echo:
    level, mid, how = "api", models[0], "response body named a model and no gateway signal was seen"
elif trust == "router":
    level, mid, how = "router", a.model, "a gateway signal was seen: the alias is a route label, the deployment is recorded separately"
else:
    level, mid, how = "manual", a.model, "no usable evidence on the wire: only a declaration is possible"
deployments_stable = len(models) <= 1 and not varying
critical_ok = (level == "api" and a.disclosure == "public" and fam != "FAMILY-TBD")
reviewer_ok = tc and fam != "FAMILY-TBD" and level in ("api", "router")

if fam == "FAMILY-TBD":
    asks.append("Which model family is behind this endpoint? prov.py compares family *strings* (verify_session in tools/prov.py); an unknown or vendor-internal label counts as 'different' from every other family, so it could satisfy the dissimilar-review rule falsely (principle 12). Do not guess.")
if level == "router":
    asks.append("Map each deployment name the router returns to a model and family (the owner resolves it), and keep request logs (call id) for the retention period (principle 6).")
if level == "manual":
    asks.append("Return the serving model id per response (body 'model' field or a header), or provide per-request logs keyed by a request id.")
if len(models) > 1 or varying:
    asks.append("Is the alias pinned? State how deployment switches are announced; each switch changes what a recall must cover.")
if echo and level != "router":
    asks.append("The body only echoes the alias. Provide the real model id in a response field or header.")
if not tc:
    asks.append("Tool calling did not work through this endpoint; an agent harness will not run on it (check the provider's tool/function-calling support).")

print("=" * 72)
print(f"Provider probe: {a.base}  alias={a.model}")
for lv, m in findings: print(f"[{lv:4}] {m}")
print("-" * 72)
print("Suggested provenance configuration (draft; nothing written to the repository)")
print(f"  evidence level achievable : {level}  ({how})")
print(f"  capture proxy needed      : {'yes' if level in ('api','router') else 'no (it would record nothing)'}")
print(f"  model_id for the profile  : {mid}")
print(f"  model family              : {fam}{'  <-- operator must supply' if fam == 'FAMILY-TBD' else ''}")
print(f"  disclosure                : {a.disclosure}" + ("  (withheld: not allowed to write critical paths)" if a.disclosure == 'withheld' else ""))
print(f"  scopes it can carry       : docs, tests, build, ci, packaging" + (", refactor, code (incl. critical paths)" if critical_ok else ", code outside critical paths only until: public + known family + api-level evidence"))
print(f"  usable as dissimilar reviewer : {'yes' if reviewer_ok else 'no (needs tool calling, a known family and wire evidence)'}")
print(f"  alias stable in this probe: {'yes' if deployments_stable else 'NO - re-run at other times of day; see asks'}")
print()
print("Draft profile (.provenance/profiles/%s/r1.toml); FAMILY-TBD fails the schema on purpose:" % a.profile)
print(f'schema_version = "1.0"\nid = "{a.profile}"\nrevision = 1\nharness = "{a.harness}"\nowner = "TBD"\nstatus = "active"\n\n[[roles]]\nname = "implementer"\nmodel_family = "{fam}"\nmodel_id = "{mid}"\ndisclosure = "{a.disclosure}"')
print()
print("Asks for the operator / LLM admin (minimal, concrete):" if asks else "No operator asks derived from this probe.")
for x in asks: print("  - " + x)
print()
print("Next steps (human): decide owner and family, commit the profile in its own PR, then run a real session")
print("through tools/provcap-proxy.py and `prov declare --evidence capture-log:FILE`; re-probe on another day.")
