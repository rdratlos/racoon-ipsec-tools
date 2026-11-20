#!/bin/sh
# kind_preflight NAME ARGS: prove the host can run live rows at all.
# This is a row (not just a runner prelude) so the reason a host cannot run
# the live tier shows up in the report next to every other result.
kind_preflight() {
	if reason=$(preflight); then
		log "preflight OK: kernel $(uname -r)"
		return 0
	fi
	skip "$reason"
	return 0
}
