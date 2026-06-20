#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"
BUILD_DIR="$SRC/build"
APP_NAME="OpenPubkeyAgent"
BUNDLE_DIR="$BUILD_DIR/${APP_NAME}.app"
BIN_PATH="$BUNDLE_DIR/Contents/MacOS/${APP_NAME}"

mkdir -p "$BUILD_DIR"
cd "$SRC"

echo "Building binary..."
go build -o "$BUILD_DIR/${APP_NAME}"

echo "Creating .app bundle structure..."
mkdir -p "$BUNDLE_DIR/Contents/MacOS"
mkdir -p "$BUNDLE_DIR/Contents/Resources"

mv "$BUILD_DIR/${APP_NAME}" "$BIN_PATH"

cat > "$BUNDLE_DIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>${APP_NAME}</string>
	<key>CFBundleDisplayName</key>
	<string>${APP_NAME}</string>
	<key>CFBundleExecutable</key>
	<string>${APP_NAME}</string>
	<key>CFBundleIdentifier</key>
	<string>com.example.openpubkeyagent</string>
	<key>CFBundleVersion</key>
	<string>0.1.0</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
</dict>
</plist>
EOF

echo ".app bundle created at $BUNDLE_DIR"

echo "To install in /Applications run: sudo cp -R \"${BUNDLE_DIR}\" /Applications/"
