#!/usr/bin/env bash
# G2.1-G2.5, G2.8: mounts. G2.7 is answered by the schema (flat [[mounts]] and [[mounts.default]] are both accepted).
# G2.6, G2.9 need manual variants. Note `coi trust` approves out-of-workspace mounts from a PROJECT .coi/config.toml;
# profiles under ~/.coi/profiles are expected to be trusted scope (unverified).
. "$(dirname "$0")/../lib.sh"
bash "$(dirname "$0")/fixtures.sh" >/dev/null
M="$SCRATCH_MOUNT"; rm -rf "$M"; mkdir -p "$M"; echo token-v1 > "$M/token"
# Keys per schema MountEntry: host, container, readonly, shift.
write_profile t-mnt "$(cat "$PROFILES/t-a/config.toml")

[[mounts]]
host = \"$M\"
container = \"/run/t-mount\""

t_begin G2.1 "[[mounts]] outside workspace"
t_run coi_exec t-mnt ls -la /run/t-mount
t_sh "$INCUS_BIN config device show \"$(coi_container)\""
t_note "Profile mounts outside the workspace may be gated like project mounts (see coi trust help); if the device is missing, that is the finding."
if contains "$LAST_OUT" /run/t-mount; then t_end PASS "device present" "-"; else t_end FAIL "mount not configured" "check schema table name"; fi

t_begin G2.2 "read-only flag"
write_profile t-mnt-ro "$(cat "$PROFILES/t-a/config.toml")

[[mounts]]
host = \"$M\"
container = \"/run/t-mount\"
readonly = true"
t_run coi_exec t-mnt    bash -c 'touch /run/t-mount/rw && echo WRITABLE; rm -f /run/t-mount/rw'
t_run coi_exec t-mnt-ro bash -c 'touch /run/t-mount/ro && echo WRITABLE || echo READONLY'
if contains "$LAST_OUT" READONLY; then t_end PASS "readonly = true blocks writes" "setup page: mounts"; else t_end FAIL "readonly mount was writable" "coi caveat"; fi

t_begin G2.3 "host atomic replace"
t_run coi_exec t-mnt cat /run/t-mount/token; a="$LAST_OUT"
echo token-v2 > "$M/token.new"; mv "$M/token.new" "$M/token"
t_run coi_exec t-mnt cat /run/t-mount/token; b="$LAST_OUT"
if contains "$b" v2; then t_end PASS "replace visible ($a -> $b)" "token option C"; else t_end FAIL "replace NOT visible: $a -> $b" "token option C"; fi

t_begin G2.4 "host in-place edit"
echo token-v3 > "$M/token"
t_run coi_exec t-mnt cat /run/t-mount/token
if contains "$LAST_OUT" v3; then t_end PASS "in-place edit visible" "token option C"; else t_end FAIL "in-place edit NOT visible" "token option C"; fi

t_begin G2.5 "ownership and mode"
for mode in 0640 0644; do
  chmod "$mode" "$M/token"
  t_run coi_exec t-mnt bash -c 'id; ls -ln /run/t-mount/token; cat /run/t-mount/token >/dev/null && echo READ-OK || echo READ-DENIED'
done
t_note "host owner: $(stat -c '%u:%g %a' "$M/token"). Re-run as a different host user for the full matrix."
t_end OBSERVED "uid/gid mapping per mode in raw output" "token option C: file mode guidance"

t_begin G2.8 "missing host path"
miss="/tmp/t-does-not-exist"; rm -rf "$miss"
write_profile t-mnt2 "inherits = \"t-base\"
[[mounts]]
host = \"$miss\"
container = \"/run/t-missing\""
t_run coi_exec t-mnt2 ls -la /run/t-missing
t_sh "ls -ld '$miss' 2>&1"
t_end OBSERVED "error or silent creation (and owner) in raw output" "coi caveats"
