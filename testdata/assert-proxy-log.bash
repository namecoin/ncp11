#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

DESIRED="$1"

if [[ "$DESIRED" != "present" ]] && [[ "$DESIRED" != "missing" ]]
then
    echo "Invalid DESIRED value; should be present or missing"
    exit 1
fi

if [[ -e "$HOME/.config/ncp11.log" ]] || [[ -e "./ncp11.log" ]]
then
    RESULT="present"
else
    RESULT="missing"
fi

rm -f "$HOME/.config/ncp11.log"
rm -f "./ncp11.log"

if [[ "$RESULT" != "$DESIRED" ]]
then
    echo "Log test failed"
    echo "Got $RESULT, wanted $DESIRED"
    exit 1
fi

exit 0
