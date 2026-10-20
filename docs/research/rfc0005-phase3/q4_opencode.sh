#!/bin/sh
# Q4: run OpenCode against router_mock.py as a custom OpenAI-compatible
# provider and collect what each capture point sees. Throw-away directory
# only: HOME and the XDG directories are redirected and the environment is
# cleared, so the user's ~/.config/opencode and ~/.local/share/opencode are
# never touched.
#
# usage: q4_opencode.sh [WORKDIR] [OPENCODE_BIN]
#   OPENCODE_BIN default: `opencode` on PATH. To get one without a global
#   install:  npm install --prefix "$WORKDIR/npm" opencode-ai@1.19.3
#   then pass "$WORKDIR/npm/node_modules/.bin/opencode".
# The requested model id is "kitch-coder-latest"; the mock answers as
# "KITCH-Coder" and names the deployment in x-litellm-* headers, so the
# store shows whether OpenCode records the requested or the returned model.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=${1:-$(mktemp -d)}
oc=${2:-$(command -v opencode)}
port=${PORT:-8789}

mkdir -p "$work/home" "$work/repo/.opencode/plugin" "$work/out"
cp "$here/provprobe-plugin.js" "$work/repo/.opencode/plugin/provprobe.js"
cat > "$work/repo/opencode.json" <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "model": "kitch/kitch-coder-latest",
  "autoupdate": false,
  "share": "disabled",
  "provider": {
    "kitch": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "KITCH router (mock)",
      "options": { "baseURL": "http://127.0.0.1:$port/v1", "apiKey": "dummy" },
      "models": { "kitch-coder-latest": { "name": "KITCH Coder (alias)" } }
    }
  },
  "permission": { "bash": "allow" }
}
EOF
git -C "$work/repo" init -q

python3 "$here/router_mock.py" --port "$port" --switch-every 1 \
    --probe-command 'env | grep -E "^(OPENCODE|AGENT|AI_AGENT|CLAUDECODE)=" | sort' \
    --log "$work/out/router.jsonl" > "$work/out/mock.log" 2>&1 &
mock=$!
trap 'kill $mock 2>/dev/null || true' EXIT INT TERM
sleep 1

cd "$work/repo"
env -i PATH="$(dirname "$oc"):/usr/bin:/bin" HOME="$work/home" \
    XDG_CONFIG_HOME="$work/home/.config" XDG_DATA_HOME="$work/home/.local/share" \
    XDG_CACHE_HOME="$work/home/.cache" XDG_STATE_HOME="$work/home/.local/state" \
    PROVPROBE_LOG="$work/out/provprobe.jsonl" \
    OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_AUTOUPDATE=1 \
    OPENCODE_DISABLE_DEFAULT_PLUGINS=1 OPENCODE_DISABLE_CLAUDE_CODE=1 \
    "$oc" run --print-logs "Run one shell command, then tell me which model you are." \
    > "$work/out/stdout.txt" 2> "$work/out/stderr.log" || true

echo "workdir: $work"
echo "== router log (ground truth)"
jq -c '{n, requested_model, deployment, response_model}' "$work/out/router.jsonl"
echo "== plugin hooks"
jq -c 'select(.hook != "event")' "$work/out/provprobe.jsonl"
echo "== answer"
tail -c 600 "$work/out/stdout.txt"; echo
echo "== session store files"
find "$work/home/.local/share/opencode" -maxdepth 3 | head -20
