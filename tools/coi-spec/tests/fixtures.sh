#!/usr/bin/env bash
# Spec §2 fixtures, with table names taken from the real schema (discovery/schema-profile.txt):
# persistent/session_name live under [container]; env_commands is top-level and trusted-scope only.
. "$(dirname "$0")/../lib.sh"
write_profile t-base '[container]
persistent = true
session_name = "t-shared"

[environment]
T_ENV = "from-profile-v1"

[env_commands]
T_CMD = "date +%s.%N"'
write_profile t-a 'inherits = "t-base"

[environment]
T_WHO = "profile-a"'
write_profile t-b 'inherits = "t-base"

[environment]
T_WHO = "profile-b"'
mkdir -p "$RESULTS/discovery"; $COI_BIN profile info t-a > "$RESULTS/discovery/profile-info-t-a.txt" 2>&1
echo "fixtures written to $PROFILES"
