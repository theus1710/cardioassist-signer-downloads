# CardioAssist Signer

Java 17 LTS Swing signer using Apache PDFBox and Bouncy Castle (permissive licenses; no AGPL component).

## Build and server validation

```sh
mvn test package
java -jar target/cardioassist-signer.jar 'cardioassist-signer://sign?session=42&launch=LAUNCH_CODE&pairing=PAIRING_CODE'
java -jar target/cardioassist-signer.jar --validate unsigned.pdf signed.pdf 12345678909
```

The validator prints exactly one JSON object (`valid`, `errorCode` on failure; protocol, CPF, and public certificate metadata on success) and exits nonzero on any error (`2` for incorrect arguments). It checks ByteRange/CMS integrity, strict original-prefix incremental binding, certificate dates/key usage, CPF checksum and ICP-Brasil CPF SAN OID `2.16.76.1.3.1`. PKIX paths are built only to the four bundled, SHA-256-pinned current general ICP-Brasil roots (v5, v6, v7 and v12); SSL v10, code-signing v11, JVM roots, and roots supplied only by CMS are not trusted. OCSP/CRL revocation checking is hard-fail, so unavailable or indeterminate status rejects the signature.

The packaged client is pinned to the official `https://cardioassistant.top` production endpoint and refuses non-HTTPS values. A developer may override it locally with `-Dcardioassist.baseUrl=https://...`. The launch URI carries `session`, `launch`, and `pairing`. It claims `POST /api/signer/sessions/:session/claim` with `launchCode`, displays `pairing`, then polls `GET /api/signer/sessions/:session` until `APPROVED` before fetching `/document`. Pairing and scoped session tokens are only held in memory.

## Certificates

A1 PKCS#12 PFX/P12 files are supported. Passwords and token PINs are used only in a local `char[]`, immediately wiped, and never persisted or logged. Windows uses `Windows-MY`; macOS uses `KeychainStore`. A3 support depends on the token vendor's installed middleware exposing keys through those stores. Some drivers expose only PKCS#11, use proprietary dialogs, or do not work with the JDK provider: this application does **not** claim universal A3 compatibility.

## Packaging and release installers

The release workflow at [`.github/workflows/signer-release.yml`](../../.github/workflows/signer-release.yml)
tests the Maven project once, then packages native installers on their native
runners. It publishes the following exact filenames:

- `CardioAssistSigner-Windows-x64.exe`
- `CardioAssistSigner-macOS-arm64.dmg`
- `CardioAssistSigner-macOS-x64.dmg`
- `SHA256SUMS.txt` and `release-manifest.json`

For an unsigned local test build, use the native host with JDK 17 and jpackage
(Windows also needs Inno Setup 6):

```powershell
./scripts/package-windows.ps1 -Version 1.0.0
```
```sh
./scripts/package-macos.sh 1.0.0 arm64
```

Unsigned installers are useful only for testing: Windows SmartScreen and macOS
Gatekeeper may warn. The workflow records `signed:false` (and
`notarized:false`) in `release-manifest.json` for those builds; do not present
them as official releases. The manifest sets `official:true` only when Windows
is signed and both macOS builds are signed and notarized.

Official Windows releases require repository secrets
`WINDOWS_CERTIFICATE_BASE64` (base64-encoded PFX) and
`WINDOWS_CERTIFICATE_PASSWORD`. The certificate is decoded only in the runner,
then `signtool /fd SHA256` signs both the app executable and the final Inno
Setup installer. Windows registration is per-user at
`HKCU\Software\Classes\cardioassist-signer`; its open command supplies the full
`"%1"` URI to the installed executable. The installer also creates Start-menu
(optional desktop) shortcuts and standard uninstall metadata.

Official macOS releases require all of
`MACOS_CERTIFICATE_P12_BASE64`, `MACOS_CERTIFICATE_PASSWORD`,
`APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_APP_PASSWORD`, and
`APPLE_TEAM_ID`. The workflow imports the P12 into a temporary keychain; the
packager applies hardened-runtime signing, submits the DMG to `notarytool`, and
staples it. The bundle identifier is `br.com.cardioassist.signer` and its
`Info.plist` declares the `cardioassist-signer` URL scheme. Keep certificates,
Apple credentials, and passwords in GitHub **Actions secrets**, never in
repository variables or source files. The workflow can be copied to the public
downloads repository, but it requires the signer source to remain at
`native/cardioassist-signer`.