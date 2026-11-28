#!/usr/bin/env bash
# Spec §2 fixtures. Table names follow the spec; the schema wins (see discovery/schema-profile.txt).
. "$(dirname "$0")/../lib.sh"
write_profile t-base 'persistent = true
session_name = "t-shared"

[environment]
T_ENV = "from-profile-v1"

[defaults.env_commands]
T_CMD = "date +%s.%N"'
write_profile t-a 'inherits = "t-base"
session_name = "t-shared"

[environment]
T_WHO = "profile-a"'
write_profile t-b 'inherits = "t-base"
session_name = "t-shared"

[environment]
T_WHO = "profile-b"'
$COI_BIN profile info t-a > "$RESULTS/discovery/profile-info-t-a.txt" 2>&1
echo "fixtures written to $PROFILES"
