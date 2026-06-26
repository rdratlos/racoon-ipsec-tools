#!/bin/bash
# setup-dev-env.sh — configure local Git settings required
# for working with this repository.
#
# Run once after cloning:
#   bash scripts/setup-dev-env.sh

set -e

echo "Configuring local Git settings for racoon-ipsec-tools..."

# Required for .gitattributes merge=ours on debian/control,
# debian/compat, and debian/rules.
# Without this, Git errors with "no such merge driver" when
# rebasing Ubuntu LTS branches onto develop.
git config merge.ours.driver true
echo "  merge.ours.driver = true"

echo "Done. Local Git configuration is ready."
