# Xiaomi X20 Max Diagnostic

Android diagnostic app for **Xiaomi Robot Vacuum X20 Max** (`xiaomi.vacuum.d109gl`).

The app communicates directly with the robot over the local Wi-Fi network using Xiaomi's MiIO LAN protocol (UDP/54321) and reads MIoT properties with `get_properties`.

## v0.3.0 browser-session login

For single-phone token retrieval, the app opens a **dedicated Xiaomi login WebView** that loads the official `account.xiaomi.com` page. That WebView has no JavaScript bridge to the diagnostic app. The user enters credentials, CAPTCHA, or 2FA directly into Xiaomi's page; the diagnostic code never receives the Xiaomi password.

After login, the app reuses only the authenticated Xiaomi browser cookies to request the user's own device metadata/token from Xiaomi Cloud. QR login remains available as an optional second-screen method.

## Current diagnostic focus

- local MiIO IP scan without token
- `2/3` — `fault`
- `2/18` — `base-station-working-status`
- `2/53` — `water-check-list`
- `2/54` — `water-check-status`
- `2/60` — `mop-water-output-level-no-tank`
- `2/61` — `frequency-mop-wash-no-tank`
- `2/62` — `auto-water-change-installed`
- `2/66` — `fault-ids`
- `2/67` — `action-result`
- `2/72` — `notice`

It can also scan **SIID 2 / PIID 1–100** and compare Snapshot A vs Snapshot B to reveal which readable states change when the dirty-water tank or wash tray is removed/reinstalled.

## Safety

The local robot protocol implementation is intentionally **read-only**. It exposes MiIO `hello` and MIoT `get_properties`; it does not implement `set_properties`, movement, cleaning commands, or MIoT actions.

The app has no analytics and no server component. It does not log or persist Xiaomi account credentials.

## Build

GitHub Actions builds a debug APK. The artifact is named `X20-Max-Diagnostic-APK`.

This is an independent diagnostic utility and is not affiliated with Xiaomi.
