# AGENTS.md: Developer & Agent Guidelines for Encounter (Flutter Demo App)

> **PRIMARY DIRECTIVE FOR ALL AGENTS:**
> `encounter` is a store-ready, production-grade cross-platform demonstration application for the [`mesh_identity`](https://pub.dev/packages/mesh_identity) package.
> It targets five platforms: **iOS**, **Android**, **macOS**, **Windows**, and **Linux** (Web explicitly excluded).
> All code must maintain **strict parameterization between open-source defaults and proprietary store credentials**, ensuring anyone can build the application out of the box while official store releases inject private identifiers and signing keys at build time.

---

## 1. Core Constraints & Guardrails

### A. Confidentiality & Parameterized Build Identifiers
- **Zero Proprietary Identifiers in Git:** Never commit proprietary company domain names, real bundle identifiers (e.g. `com.<company>.encounter`), signing keystores, provisioning profiles, or private API keys to git.
- **Open-Source Fallback Defaults:** The committed codebase must always default to:
  - Application ID / Bundle ID: `org.mesh.identity.encounter`
  - App Name: `Encounter`
  - Repo URL: `https://github.com/afstanton/mesh-identity`
- **Gitignored Overrides Only:**
  - Android: `android/local.properties` (`application.id=...`) or `-PAPPLICATION_ID=...`.
  - iOS: `ios/Flutter/AppId.xcconfig` (`APP_BUNDLE_ID=...`).
  - macOS: `macos/Runner/Configs/AppId.xcconfig` (`PRODUCT_BUNDLE_IDENTIFIER=...`).
  - Dart Defines: `config/config.local.json` passed via `--dart-define-from-file=config/config.local.json`.
- Always provide committed `.example` templates (`config.example.json`, `AppId.example.xcconfig`) alongside gitignored targets.

### B. Dependency Invariant
- **Published Package Only:** `pubspec.yaml` must depend on `mesh_identity` from **pub.dev** (`mesh_identity: ^0.5.0`).
- **Never use local path dependencies** (`path: ../../..`) in `pubspec.yaml`.

### C. Optional Telemetry & Analytics
- **Strictly Optional & Disabled by Default:** Zero analytics, telemetry, or crashlytics tracking may run by default.
- **Null Object Pattern:** Implement an abstract `TelemetryService` with a `NoOpTelemetryService` default.
- **Conditional Initialization:** Telemetry SDKs or network connections may only activate if explicitly enabled via compile-time flags (`--dart-define=ENABLE_ANALYTICS=true` or `config.local.json`) AND valid keys are present.
- **Platform Files Gitignored:** Files such as `GoogleService-Info.plist`, `google-services.json`, and `sentry.properties` must remain strictly gitignored.

### D. Platform Store Guidelines & UI Conventions
- **macOS App Store:** The Mac app must adhere to Apple Human Interface Guidelines:
  - Native unified toolbar style (`toolbarStyle = .unified` in `MainFlutterWindow.swift`).
  - App Sandbox entitlements (`com.apple.security.network.client`, camera, bluetooth) in `Release.entitlements`.
- **Responsive Navigation:**
  - Desktop (macOS, Windows, Linux): Responsive window sizing with native top titlebar integration and sidebar/rail navigation.
  - Mobile (iOS, Android): Standard safe-area padding and bottom navigation bar.
- **Transport Degradation:**
  - Optical QR Code transport (`QrTransport`) must function universally across all platforms (webcam/camera scanner, on-screen display, and clipboard/file import fallback).
  - Bluetooth Low Energy transport (`BleTransport`) must be cleanly decoupled behind an abstract `EncounterTransport` interface and degrade gracefully on hardware/platforms without BLE support or permissions.

### E. Memory Safety & Concurrency
- **Single-Isolate Native Handles:** As specified in `mesh_identity`, `MeshInstallation` and `MeshGroupHandle` wrap raw C-ABI pointers without internal multi-thread locks. Do NOT share or access native handle instances concurrently across multiple Dart isolates.
- **Seed Security & Zeroization:** Personas require caller-managed 32-byte signing seeds. Sensitive Dart `Uint8List` buffers containing seeds or passphrases should be cleared with `fillRange(0, 32, 0)` when discarded.

---

## 2. Working Standards for Agents

Before completing any task or pull request on this app, always verify:

1. **Test Suite:**
   ```bash
   flutter test
   ```
2. **Analysis & Lints:**
   ```bash
   dart analyze --fatal-infos
   ```
3. **Code Formatting:**
   ```bash
   dart format --output=none --set-exit-if-changed .
   ```
4. **Manifest & Git Hygiene:**
   - Confirm no private files or keys (`config.local.json`, `AppId.xcconfig`, keystores) are tracked in `git status`.
   - Confirm `pubspec.yaml` references `mesh_identity` via pub.dev version constraints.
