# Encounter (Flutter Reference App)

A cross-platform reference and demonstration application for **[`mesh_identity`](https://pub.dev/packages/mesh_identity)**, demonstrating cryptographic peer identity lifecycle, in-person Encounter ceremonies (QR and Bluetooth Low Energy), contact governance, Byzantine group admission, device-to-device handoff, and OpenPGP cross-certification.

Target Platforms: **iOS**, **Android**, **macOS**, **Windows**, and **Linux** (Web excluded).

> **Current Status**: Foundation phase. Native integration with `mesh_identity` v0.5.0 from pub.dev, build-time parameterization, and end-to-end smoke tests are verified. Feature screens and UI controllers are actively under development.

---

## 1. Feature Roadmap & Status

| Capability | Status | Description |
|---|---|---|
| **Native Integration** | **Complete** | Proven FFI bindings via `mesh_identity` v0.5.0 on pub.dev. |
| **Build-Time Parameterization** | **Complete** | Confidential store IDs via gitignored xcconfig & gradle properties. |
| **Practice Mode Encounter** | **In Progress** | Single-device Alice & Bob ceremony with 6-digit SAS verification. |
| **Secure Persistence** | **In Progress** | Platform Keychain/Keystore seed storage & atomic snapshot writes. |
| **Optical QR Transport** | **Planned** | Dynamic QR code generation, camera scanning, and clipboard/file import. |
| **BLE Transport** | **Planned** | Offline Bluetooth Low Energy advertisement & GATT exchange. |
| **OpenPGP & Groups** | **Planned** | Cross-certification preview disclosures & Byzantine group admission. |
| **About Screen** | **Planned** | In-app license and public repository link (`https://github.com/afstanton/mesh-identity`). |

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

- **macOS App Store**: Window uses native unified top toolbar styling (`toolbarStyle = .unified`) compliant with Apple Human Interface Guidelines.
- **In-App Open Source Attribution**: Includes a dedicated "About" screen displaying the license, cryptographic library version, and a direct link to the public repository.
- **Hardware & Transports**:
  - **Optical QR Transport**: Supported across all desktop and mobile platforms (camera scanning on mobile/webcam, on-screen QR presentation, and text/clipboard import fallback).
  - **Bluetooth Low Energy (BLE)**: Offline peer discovery and ceremony exchange without local Wi-Fi or cellular connectivity.

---

## 5. License

MIT License. See the root [`LICENSE`](../../LICENSE) file.
