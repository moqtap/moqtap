#!/bin/sh
# Usage: sync-fixtures.sh <directory of golden source bodies>
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <fixture directory>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
src=$1
dst=$here/fixtures/source
rm -f "$dst"/*.bin "$dst"/manifest.json
cp "$src"/*.bin "$dst"/
sed '/"note": /d' "$src"/manifest.json > "$dst"/manifest.json
