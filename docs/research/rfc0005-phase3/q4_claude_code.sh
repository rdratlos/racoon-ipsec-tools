#!/bin/sh
# Q4: run Claude Code against router_mock.py and collect what each capture
# point sees. Everything lives in a throw-away directory; the user's own
# ~/.claude is never read or written (HOME and CLAUDE_CONFIG_DIR are
# redirected, the environment is cleared with env -i).
#
# usage: q4_claude_code.sh [WORKDIR] [REQUESTED_MODEL]
#   WORKDIR          default: a new mktemp -d
#   REQUESTED_MODEL  default: claude-opus-5-5
# Needs: claude (Claude Code CLI) on PATH, python3, jq. No credentials: the
# API key is a dummy and the base URL is the local mock.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=${1:-$(mktemp -d)}
model=${2:-claude-opus-5-5}
port=${PORT:-8787}
claude_bin=$(command -v claude)

mkdir -p "$work/home/.claude" "$work/repo" "$work/out"
: > "$work/out/hooks.jsonl"
echo "Run one shell command, then tell me which model you are." > "$work/out/prompt.txt"

# Hook command: append the raw stdin JSON of every event to hooks.jsonl.
hook="cat >> '$work/out/hooks.jsonl'; echo >> '$work/out/hooks.jsonl'"
cat > "$work/home/.claude/settings.json" <<EOF
{
  "hooks": {
    "SessionStart":     [{"hooks": [{"type": "command", "command": "$hook"}]}],
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "$hook"}]}],
    "PreToolUse":       [{"matcher": "*", "hooks": [{"type": "command", "command": "$hook"}]}],
    "PostToolUse":      [{"matcher": "*", "hooks": [{"type": "command", "command": "$hook"}]}],
    "Stop":             [{"hooks": [{"type": "command", "command": "$hook"}]}],
    "PostModelSwitch":  [{"hooks": [{"type": "command", "command": "$hook"}]}],
    "SessionEnd":       [{"hooks": [{"type": "command", "command": "$hook"}]}]
  },
  "statusLine": {"type": "command", "command": "cat >> '$work/out/statusline.jsonl'; echo"}
}
EOF

git -C "$work/repo" init -q

python3 "$here/router_mock.py" --port "$port" --switch-every 1 \
    --log "$work/out/router.jsonl" > "$work/out/mock.log" 2>&1 &
mock=$!
trap 'kill $mock 2>/dev/null || true' EXIT INT TERM
sleep 1

cd "$work/repo"
env -i PATH="$(dirname "$claude_bin"):/usr/bin:/bin" HOME="$work/home" \
    CLAUDE_CONFIG_DIR="$work/home/.claude" \
    ANTHROPIC_BASE_URL="http://127.0.0.1:$port" \
    ANTHROPIC_API_KEY="sk-ant-dummy-not-a-real-key" \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1 \
    "$claude_bin" -p --model "$model" --output-format json \
        --allowedTools "Bash(echo provenance-probe)" \
        < "$work/out/prompt.txt" > "$work/out/result.json" 2> "$work/out/stderr.log" || true

echo "workdir: $work"
echo "== router log (ground truth)"
jq -c '{n, path, requested_model, deployment, response_model}' "$work/out/router.jsonl"
echo "== -p result"
jq -c '{result, modelUsage: (.modelUsage // {} | keys)}' "$work/out/result.json" 2>/dev/null \
    || head -c 600 "$work/out/result.json"
echo "== hook events: name -> model-ish fields"
jq -c 'select(.) | {e: .hook_event_name, model, from_model, to_model,
       keys: (keys | map(select(test("model|agent"))))}' "$work/out/hooks.jsonl"
echo "== transcript: per assistant message"
find "$work/home/.claude/projects" -name '*.jsonl' -exec cat {} + |
    jq -c 'select(.type == "assistant") | {model: .message.model,
           requestedModel, id: .message.id, version}'
echo "== statusline input (interactive only)"
[ -s "$work/out/statusline.jsonl" ] && jq -c '.model' "$work/out/statusline.jsonl" || echo "(none: -p mode)"
