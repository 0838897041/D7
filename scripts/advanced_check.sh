#!/bin/sh
BASEDIR="$(cd "$(dirname "$0")" && pwd)/.."
for f in "$BASEDIR/to_validate"/*.json; do
  [ -f "$f" ] || continue
  echo "Validating $f"
  python3 "$BASEDIR/app_v2.py" validate "$f"
done
