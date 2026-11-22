# Encounter (Flutter Reference App)

A cross-platform reference and demonstration application for **[`mesh_identity`](https://pub.dev/packages/mesh_identity)**, demonstrating cryptographic peer identity lifecycle, in-person Encounter ceremonies (QR and Bluetooth Low Energy), contact governance, Byzantine group admission, device-to-device handoff, and OpenPGP cross-certification.

Target Platforms: **iOS**, **Android**, **macOS**, **Windows**, and **Linux** (Web excluded).

> **Current Status**: Core Node, Responsive Shell, In-Person Encounter ceremonies, and Contact Governance & Persona Management complete (Slices 1–4). Native integration with `mesh_identity` v0.5.1, transactional keyring + generational snapshot persistence, responsive adaptive shell, macOS HIG menu/toolbar, About screen, isolated single-device Practice Mode, two-device QR/URI encounter verification, contact search/alias/block/import UI, and multi-persona switching/removal are complete. Hardware Camera QR Scanning is next (Slice 5).

---

## 1. Feature Roadmap & Status

| Capability | Status | Description |
|---|---|---|
| **Native Integration** | **Complete** | Proven FFI bindings via `mesh_identity` v0.5.1 on pub.dev. |
| **Build-Time Parameterization** | **Complete** | Confidential store IDs via gitignored xcconfig & gradle properties. |
| **Secure Persistence** | **Complete** | Keychain/Keystore seed storage, envelope framing & generational atomic snapshots. |
| **Responsive Shell & HIG** | **Complete** | Adaptive bottom bar / navigation rail, themes, and macOS unified toolbar + menu bar. |
| **About Screen** | **Complete** | In-app MIT license, engine versions, and public repository link (`https://github.com/afstanton/mesh-identity`). |
| **Practice Mode Encounter** | **Complete** | Isolated single-device Alice & Bob ceremony with 6-digit SAS verification. |
| **Manual & QR Encounter** | **Complete** | Two-device optical QR display (`QrTransport.encodeUri`), clipboard URI import, statutory notices, timeout & rate-limit handling. |
| **Contacts & Personas UI** | **Complete** | Contact search/filters, detail cards, alias editing, blocking/unblocking, unverified key import, and multi-persona switching (Slice 4). |
| **Camera QR Scanner** | **Next** | Hardware camera barcode scanning with entitlements & fallback (Slice 5). |
| **Device Handoff & Groups** | **Planned** | Voting role handoff, Byzantine group admission, and two-phase commit outbox (Slices 6–7). |
| **OpenPGP & BLE** | **Planned** | OpenPGP export previews/cross-certification and offline BLE transport (Slices 8–9). |

---

## 1. Quick Start (Open-Source Build)

This project builds cleanly out of the box with zero required configuration. All dependencies are fetched directly from [pub.dev](https://pub.dev/packages/mesh_identity).

```bash
# Get dependencies
flutter pub get

# Run on your connected device or desktop
flutter run -d macos    # or ios, android, windows, linux
```

By default, the application builds with public open-source placeholders:
- **Application ID / Bundle ID**: `org.mesh.identity.encounter`
- **Analytics & Crashlytics**: Disabled (zero tracking / telemetry code active)
- **Repo Link**: `https://github.com/afstanton/mesh-identity`

---

## 2. Build-Time Parameterization for App Store Releases

To publish official releases to the Apple App Store, Google Play Store, or Microsoft Store under proprietary company identifiers and signing keys without leaking secrets to public git, configure the gitignored overrides described below.

### A. Android Application ID

Override `org.mesh.identity.encounter` by adding `application.id` to your gitignored `android/local.properties`:

```properties
# android/local.properties
application.id=com.yourcompany.encounter
```

Alternatively, pass it dynamically during CI/CD build commands:
```bash
flutter build appbundle -PAPPLICATION_ID=com.yourcompany.encounter
```

### B. iOS Bundle Identifier

Copy the example xcconfig template to the gitignored `AppId.xcconfig`:

```bash
cp ios/Flutter/AppId.example.xcconfig ios/Flutter/AppId.xcconfig
```

Edit `ios/Flutter/AppId.xcconfig`:
```xcconfig
APP_BUNDLE_ID = com.yourcompany.encounter
```

### C. macOS Bundle Identifier

Copy the example xcconfig template to the gitignored `AppId.xcconfig`:

```bash
cp macos/Runner/Configs/AppId.example.xcconfig macos/Runner/Configs/AppId.xcconfig
```

Edit `macos/Runner/Configs/AppId.xcconfig`:
```xcconfig
PRODUCT_BUNDLE_IDENTIFIER = com.yourcompany.encounter
```

---

## 3. Optional Analytics & Crash Reporting

Telemetry and analytics are **completely optional** and strictly disabled by default.

To enable telemetry for store builds:
1. Copy `config/config.example.json` to the gitignored `config/config.local.json`:
   ```bash
   cp config/config.example.json config/config.local.json
   ```
2. Set your configuration values in `config/config.local.json`:
   ```json
   {
     "APP_NAME": "Encounter",
     "REPO_URL": "https://github.com/afstanton/mesh-identity",
     "ENABLE_ANALYTICS": true,
     "ANALYTICS_KEY": "your_private_analytics_key",
     "ENABLE_CRASH_REPORTING": true,
     "CRASH_REPORTING_KEY": "your_private_crashlytics_dsn"
   }
   ```
3. Pass the config file when building:
   ```bash
   flutter build ipa --dart-define-from-file=config/config.local.json
   flutter build appbundle --dart-define-from-file=config/config.local.json
   ```

Platform files such as `GoogleService-Info.plist`, `google-services.json`, and `sentry.properties` are strictly gitignored. If those files or the `--dart-define` flags are omitted, the app initializes a null-object (`NoOpTelemetryService`), ensuring zero tracking overhead or network connections.

---

## 4. Platform-Specific Store Features

- **macOS Keychain & Sandbox**: macOS uses the OS login keychain (`usesDataProtectionKeychain: false`) so sandboxed unsigned and CI builds run without provisioning-profile `-34018` entitlement errors (the first run may display a standard macOS Keychain access prompt).
- **macOS Window & Menu Integration**: Window uses native unified top toolbar styling (`toolbarStyle = .unified`) with an `NSToolbar` and native `PlatformMenuBar` compliant with Apple Human Interface Guidelines.
- **CI Verification**: GitHub Actions verifies formatting, strict analysis, Flutter tests, and debug builds on **macOS** and **Linux**. Windows, Android, and iOS CI builds will be added once `mesh_identity 0.5.1` publishes mobile/Windows triples in `native/rust-toolchain.toml`.
- **In-App Open Source Attribution**: Includes a dedicated "About" screen displaying the license, cryptographic library version, and a direct link to the public repository.
- **Hardware & Transports**:
  - **Optical QR Transport**: Supported across all desktop and mobile platforms (camera scanning on mobile/webcam, on-screen QR presentation, and text/clipboard import fallback).
  - **Bluetooth Low Energy (BLE)**: Offline peer discovery and ceremony exchange without local Wi-Fi or cellular connectivity.

---

## 5. License

MIT License. See the root [`LICENSE`](../../LICENSE) file.
