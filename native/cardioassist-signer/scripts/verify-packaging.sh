#!/usr/bin/env bash
# Static checks are portable; pass a generated .app path to inspect its plist too.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
grep -Fq 'HKCU; Subkey: "Software\Classes\cardioassist-signer"' "$root/scripts/package-windows.ps1"
grep -Fq 'ValueData: """{app}\CardioAssistSigner.exe"" ""%1"""' "$root/scripts/package-windows.ps1"
grep -Fq 'CFBundleURLSchemes:0 string cardioassist-signer' "$root/scripts/package-macos.sh"
grep -Fq 'br.com.cardioassist.signer' "$root/scripts/package-macos.sh"
if [[ $# -eq 1 ]]; then
  plist="$1/Contents/Info.plist"
  [[ -f "$plist" ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist")" == "br.com.cardioassist.signer" ]]
  /usr/libexec/PlistBuddy -c 'Print :CFBundleURLTypes:0:CFBundleURLSchemes:0' "$plist" | grep -Fxq cardioassist-signer
fi
echo "Packaging metadata checks passed."