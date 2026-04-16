#!/usr/bin/env bash
set -euo pipefail

# Build rustdoc API documentation for the moqtap site repo.
#
# Usage: ./scripts/build-docs.sh [output_dir]
#
# Generates HTML documentation for all public crates and copies it
# to the specified output directory (default: site/api).

OUTPUT_DIR="${1:-site/api}"

echo "Building API documentation..."
RUSTDOCFLAGS="--cfg docsrs" cargo doc \
    --workspace \
    --no-deps \
    --document-private-items

echo "Copying to ${OUTPUT_DIR}..."
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"
cp -r target/doc/* "${OUTPUT_DIR}/"

# Add redirect index.html
cat > "${OUTPUT_DIR}/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0; url=moqtap_codec/index.html">
</head>
<body>
    <p><a href="moqtap_codec/index.html">Redirecting to moqtap-codec documentation...</a></p>
</body>
</html>
EOF

echo "Documentation built in ${OUTPUT_DIR}/"
echo "Crates documented:"
for dir in "${OUTPUT_DIR}"/moqtap_*/; do
    basename "${dir}"
done
