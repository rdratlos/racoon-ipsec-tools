#!/bin/sh
# Probe an OpenAI-compatible LLM endpoint for what it can tell RFC 0005
# provenance, and print a suggested profile. Not used by verify or CI.
# Read-only for the repository; writes only into the work directory.
#
# usage: PROBE_API_KEY=... provider-probe.sh BASE_URL MODEL [options]
#   BASE_URL   e.g. https://llm.example.org/v1   (no trailing slash)
#   MODEL      the alias your harness will request
#   --prov FILE      path to tools/prov.py (default: tools/prov.py)
#   --proxy FILE     path to tools/provcap-proxy.py (default: tools/provcap-proxy.py)
#   --work DIR       work directory (default: mktemp -d)
#   --n N            non-streaming probes (default 6)
#   --family F       model family, ONLY if the operator told you
#   --profile ID     profile id for the draft (default: probe-<model>)
#   --harness H      harness for the draft (default: opencode)
#   --disclosure D   public|withheld (default: public)
#   --port P         local capture proxy port (default 8787)
# The key is read from the environment, passed to curl through a header file
# in WORK (mode 600) and never printed. The probes send a one-word prompt.
set -eu
base=${1:?BASE_URL}; model=${2:?MODEL}; shift 2
prov=tools/prov.py; proxy=tools/provcap-proxy.py; work=""; n=6
family=""; pid=""; harness=opencode; disc=public; port=8787
while [ $# -gt 0 ]; do case $1 in
  --prov) prov=$2; shift 2;; --proxy) proxy=$2; shift 2;; --work) work=$2; shift 2;;
  --n) n=$2; shift 2;; --family) family=$2; shift 2;; --profile) pid=$2; shift 2;;
  --harness) harness=$2; shift 2;; --disclosure) disc=$2; shift 2;; --port) port=$2; shift 2;;
  *) echo "unknown option $1" >&2; exit 2;; esac; done
here=$(cd "$(dirname "$0")" && pwd)
[ -n "$work" ] || work=$(mktemp -d); mkdir -p "$work"; umask 077
: "${PROBE_API_KEY:=}"
printf 'Authorization: Bearer %s\n' "$PROBE_API_KEY" > "$work/auth.hdr"
log="$work/capture.jsonl"; : > "$log"

python3 "$proxy" --listen "localhost:$port" --upstream "$base" --log "$log" \
    > "$work/proxy.out" 2>&1 &
pp=$!; trap 'kill $pp 2>/dev/null || true; rm -f "$work/auth.hdr"' EXIT INT TERM
sleep 1
px="http://localhost:$port"
call() { # name path json   (through the capture proxy, full headers kept)
  curl -sS --max-time 60 -D "$work/$1.hdr" -o "$work/$1.body" \
       -H "@$work/auth.hdr" -H 'Content-Type: application/json' \
       -X POST "$px$2" -d "$3" || echo "curl failed: $1" >&2; }
prompt='[{"role":"user","content":"Reply with the single word: ok"}]'
i=1; while [ $i -le "$n" ]; do
  call "plain_$i" /chat/completions "{\"model\":\"$model\",\"max_tokens\":16,\"messages\":$prompt}"
  i=$((i+1)); done
call stream_1 /chat/completions "{\"model\":\"$model\",\"max_tokens\":16,\"stream\":true,\"messages\":$prompt}"
call stream_2 /chat/completions "{\"model\":\"$model\",\"max_tokens\":16,\"stream\":true,\"messages\":$prompt}"
call tools_1 /chat/completions "{\"model\":\"$model\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"Call the function ping with no arguments.\"}],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"ping\",\"description\":\"ping\",\"parameters\":{\"type\":\"object\",\"properties\":{}}}}],\"tool_choice\":\"auto\"}"
curl -sS --max-time 30 -D "$work/models.hdr" -o "$work/models.body" -H "@$work/auth.hdr" "$px/models" || true
kill $pp 2>/dev/null || true
python3 -I "$here/analyze.py" --work "$work" --model "$model" --n "$n" --prov "$prov" \
   --family "$family" --profile "${pid:-probe-$(echo "$model" | tr 'A-Z./_' 'a-z---')}" \
   --harness "$harness" --disclosure "$disc" --base "$base"
echo "work directory (keep or delete; contains response bodies): $work"
