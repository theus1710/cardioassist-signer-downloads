#!/usr/bin/env bash
set -euo pipefail

# Build on the matching architecture runner (macos-13=x64, macos-14=arm64).
version="${1:?usage: package-macos.sh VERSION (arm64|x64) [output-dir]}"
version="${version#signer-v}"
[[ "$version" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]] || {
  echo "version must contain two or three numeric components, for example 1.0.0" >&2
  exit 2
}
arch="${2:?usage: package-macos.sh VERSION (arm64|x64) [output-dir]}"
out="${3:-dist}"
case "$arch" in arm64|x64) ;; *) echo "architecture must be arm64 or x64" >&2; exit 2;; esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/$out"
image="$out/image"
app="$image/CardioAssistSigner.app"
asset="CardioAssistSigner-macOS-${arch}.dmg"
mkdir -p "$image"
cd "$root"
[[ -f target/cardioassist-signer.jar ]] || mvn package
jpackage --type app-image --name CardioAssistSigner --app-version "$version" \
  --mac-package-identifier br.com.cardioassist.signer --input target \
  --main-jar cardioassist-signer.jar --main-class br.com.cardioassist.signer.Main --dest "$image" \
  --java-options '-Dapple.laf.useScreenMenuBar=true' \
  --java-options '-Dcardioassist.baseUrl=https://cardioassistant.top'

plist="$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Delete :CFBundleURLTypes' "$plist" 2>/dev/null || true
/usr/libexec/PlistBuddy -c 'Add :CFBundleURLTypes array' "$plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleURLTypes:0 dict' "$plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleURLTypes:0:CFBundleURLName string br.com.cardioassist.signer' "$plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleURLTypes:0:CFBundleURLSchemes array' "$plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string cardioassist-signer' "$plist"

entitlements="$out/entitlements.plist"
cat >"$entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.cs.allow-jit</key><true/>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
</dict></plist>
EOF
signed=false
notarized=false
# CI sets this only after importing a P12 and receiving every Apple secret.
if [[ "${MACOS_SIGNING_READY:-false}" == true ]]; then
  codesign --force --deep --sign "$APPLE_SIGNING_IDENTITY" --options runtime --entitlements "$entitlements" "$app"
  codesign --verify --deep --strict --verbose=2 "$app"
  signed=true
fi
hdiutil create -volname "CardioAssist Signer" -srcfolder "$app" -ov -format UDZO "$out/$asset"
if [[ "$signed" == true ]]; then codesign --force --sign "$APPLE_SIGNING_IDENTITY" "$out/$asset"; fi
if [[ "$signed" == true ]]; then
  xcrun notarytool submit "$out/$asset" --apple-id "$APPLE_ID" --password "$APPLE_APP_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
  xcrun stapler staple "$out/$asset"
  notarized=true
fi
printf '{"platform":"macos-%s","asset":"%s","signed":%s,"notarized":%s}\n' "$arch" "$asset" "$signed" "$notarized" >"$out/build-metadata.json"