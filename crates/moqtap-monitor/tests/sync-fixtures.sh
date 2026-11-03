#!/bin/sh
# Usage: sync-fixtures.sh <directory of golden v2 source bodies>
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <fixture directory>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
src=$1
dst=$here/fixtures/source/v2
mkdir -p "$dst"
rm -f "$dst"/*.bin "$dst"/*.json
cp "$src"/*.bin "$dst"/
for f in manifest.json track-keys.json; do
  sed '/"note": /d' "$src/$f" > "$dst/$f"
done
