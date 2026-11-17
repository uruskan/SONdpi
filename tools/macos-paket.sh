#!/bin/bash
# SONdpi.app (evrensel: Apple Silicon + Intel) ve sürüm zip'ini üretir.
# Kullanım (repo kökünde): tools/macos-paket.sh   ->  target/macos/SONdpi-<sürüm>-macos-universal.zip
# Gereken: rustup hedefleri aarch64-apple-darwin ve x86_64-apple-darwin, Xcode komut satırı araçları.
set -euo pipefail
cd "$(dirname "$0")/.."
VER=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
export MACOSX_DEPLOYMENT_TARGET=11.0
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

OUT=target/macos
NAME="SONdpi-$VER-macos-universal"
rm -rf "$OUT"
APP="$OUT/$NAME/SONdpi.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo -create -output "$APP/Contents/MacOS/sondpi" \
  target/aarch64-apple-darwin/release/sondpi target/x86_64-apple-darwin/release/sondpi
cp assets/macos/SONdpi.icns "$APP/Contents/Resources/SONdpi.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>tr</string>
	<key>CFBundleDisplayName</key><string>SONdpi</string>
	<key>CFBundleExecutable</key><string>sondpi</string>
	<key>CFBundleIconFile</key><string>SONdpi</string>
	<key>CFBundleIdentifier</key><string>io.github.uruskan.sondpi</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>SONdpi</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>$VER</string>
	<key>CFBundleVersion</key><string>$VER</string>
	<key>LSMinimumSystemVersion</key><string>11.0</string>
	<key>LSUIElement</key><true/>
	<key>NSHighResolutionCapable</key><true/>
	<key>NSHumanReadableCopyright</key><string>MIT lisansı</string>
</dict>
</plist>
PLIST
# Ad-hoc imza: Apple Developer ID yok; Gatekeeper ilk açılışta onay ister (OKU-macOS.txt).
codesign --force --deep --sign - "$APP"
cp tools/OKU-macOS.txt "$OUT/$NAME/OKU-macOS.txt"
cp LICENSE "$OUT/$NAME/LICENSE.txt"
(cd "$OUT" && ditto -c -k --keepParent "$NAME" "$NAME.zip")
echo "$OUT/$NAME.zip"
