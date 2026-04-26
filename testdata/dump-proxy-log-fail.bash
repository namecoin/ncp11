#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

echo ""
echo "!!!!! Test failed, dumping proxy log... !!!!!"
echo ""

cat "$HOME/.config/ncp11.log" || true
cat "./ncp11.log" || true
cat "$HOME/.config/pkcs11mod.log" || true
cat "./pkcs11mod.log" || true

exit 1
