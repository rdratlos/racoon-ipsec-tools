#!/usr/bin/env bash
# G1: when does configuration apply?
. "$(dirname "$0")/../lib.sh"
bash "$(dirname "$0")/fixtures.sh" >/dev/null
sed_env() { sed -i "s/T_ENV = \"[^\"]*\"/T_ENV = \"$1\"/" "$PROFILES/t-a/config.toml" "$PROFILES/t-base/config.toml"; }

t_begin G1.1 "t-a, T_ENV v1 -> v2 between sessions"
sed_env from-profile-v1
t_run coi_exec t-a bash -c 'env | grep ^T_'; s1="$LAST_OUT"
sed_env from-profile-v2
t_run coi_exec_resume t-a bash -c 'env | grep ^T_'; s2="$LAST_OUT"
if   contains "$s2" v2; then t_end OBSERVED "T_ENV v2 seen: [environment] applied per session" "setup page: what applies when"
elif contains "$s2" v1 && contains "$s1" v1; then t_end OBSERVED "T_ENV stayed v1: fixed at creation" "setup page: what applies when"
else t_end FAIL "inconclusive, adapter probably wrong; read raw output" "-"; fi

t_begin G1.2 "t-b against the container created by t-a"
t_run coi_exec t-b bash -c 'echo WHO=$T_WHO; hostname'
t_sh "$INCUS_BIN list -f csv -c n"; t_run $COI_BIN list   # slots may give each session its own container
n="$(grep -c . <<<"$LAST_OUT")"
t_run coi_exec t-b bash -c 'echo $T_WHO'
who="$LAST_OUT"
if   contains "$who" profile-b && [[ "$n" -le 1 ]]; then t_end OBSERVED "same container, T_WHO=profile-b: per-session environment" "decides: harnesses can share a container"
elif contains "$who" profile-a;  then t_end OBSERVED "T_WHO=profile-a: per-container environment" "decides: one container per harness"
else t_end OBSERVED "containers=$n, T_WHO=$who: see raw output" "decides topology"; fi

t_begin G1.3 "env_commands per session?"
t_run coi_exec t-a bash -c 'echo $T_CMD'; a="$LAST_OUT"
sleep 2
t_run coi_exec_resume t-a bash -c 'echo $T_CMD'; b="$LAST_OUT"
if [[ -z "$a$b" ]]; then t_end FAIL "T_CMD empty: table name wrong? check schema" "fixtures"
elif [[ "$a" != "$b" ]]; then t_end OBSERVED "values differ: executed per session" "what applies when"
else t_end OBSERVED "values equal: cached at creation" "what applies when"; fi

t_begin G1.4 "two concurrent sessions, t-a and t-b"
( coi_exec t-a bash -c 'sleep 25; echo S1-late WHO=$T_WHO CMD=$T_CMD' > "$RESULTS/.g14-s1" 2>&1 ) &
bgpid=$!
sleep 5
t_run coi_exec t-a bash -c 'echo S1 WHO=$T_WHO CMD=$T_CMD'
t_run coi_exec t-b bash -c 'echo S2 WHO=$T_WHO CMD=$T_CMD'
wait "$bgpid"; t_note "S1 after S2 ran:"; t_sh "cat '$RESULTS/.g14-s1'"
if contains "$LAST_OUT" WHO=profile-a; then t_end OBSERVED "S2 did not change S1" "concurrency note"
else t_end OBSERVED "S1 changed after S2: sessions interfere" "concurrency caveat"; fi
rm -f "$RESULTS/.g14-s1"

t_begin G1.4b "same, both sessions pinned to slot 1" "COI_SLOT=1"
export COI_SLOT=1
( coi_exec t-a bash -c 'sleep 25; echo S1-late WHO=$T_WHO' > "$RESULTS/.g14b" 2>&1 ) & bgpid=$!
sleep 5
t_run coi_exec t-b bash -c 'echo S2 WHO=$T_WHO'
wait "$bgpid"; t_sh "cat '$RESULTS/.g14b'; $COI_BIN list"; rm -f "$RESULTS/.g14b"; unset COI_SLOT
t_end OBSERVED "slot-pinned concurrent sessions: refused, queued or shared; see raw output" "coi caveat: concurrency and slots"

t_begin G1.5 "which process environment gets T_*"
t_run coi_exec t-a bash -c 'tr "\0" "\n" </proc/1/environ | grep ^T_; echo ---; tr "\0" "\n" </proc/$$/environ | grep ^T_'
t_run incus_exec bash -c 'tr "\0" "\n" </proc/1/environ | grep ^T_ || echo "none in pid 1"'
t_end OBSERVED "pid1 vs session shell environment compared in raw output" "what applies when"

t_begin G1.6 "edit profile while S1 is open"
( coi_exec t-a bash -c 'sleep 20; echo S1 T_ENV=$T_ENV' > "$RESULTS/.g16" 2>&1 ) & bg=$!
sleep 3; sed_env from-profile-v3
t_run coi_exec_resume t-a bash -c 'echo S2 T_ENV=$T_ENV'
wait "$bg"; t_sh "cat '$RESULTS/.g16'"; rm -f "$RESULTS/.g16"
t_end OBSERVED "compare S1 (running) and S2 (new) T_ENV in raw output" "what applies when"
