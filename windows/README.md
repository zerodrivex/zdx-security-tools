# 🪟 Windows Runtime Tools

This directory contains security modules and diagnostic tools intended for **Windows-based environments** as part of the **ZeroDriveX** platform.

---

## 🔧 Included Tools

### `fsod_beacon.so`

A lightweight runtime beacon module designed to:
- 📡 Trace injected signals or runtime anomalies
- 🎯 Monitor for subcarrier payload activity
- 🧾 Log indirect packet behavior for forensic review

#### ⚙️ Usage (Advanced)
This `.so` module can be injected into sandboxed or embedded runtime environments using dynamic loading methods.

While `.so` files are typically Unix-based shared objects, `fsod_beacon.so` is built to support **runtime hooks or diagnostics under emulated or cross-compiled layers** (e.g. WSL2, Cygwin, or sandboxed instrumentation tools on Windows).

> Ensure proper permissions and sandbox isolation when testing signal tracing on production systems.

---

## 📁 File List
