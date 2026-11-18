---
name: cellprobe
description: "Offline and live read-only mobile hardware battery, powerlog, thermal, storage, and cellular radio forensics for iOS and Android. Use when diagnosing phone battery drain, checking real cycle count and WeightedRa cell impedance, auditing iOS sysdiagnose archives or CurrentPowerlog.PLSQL, parsing Android dumpsys batterystats, or running secondhand iPhone hardware checks."
---

# CellProbe Mobile Forensic Skill

You are operating **CellProbe**, a read-only iOS and Android battery, powerlog, thermal, storage, and radio forensic CLI built with a zero-dependency Python Standard Library core.

## When to Use This Skill

- User connects an iPhone via USB or supplies an iOS `sysdiagnose_*.tar.gz`, `CurrentPowerlog.PLSQL`, `.EPSQL`, `.BGSQL`, or JSON snapshot for battery/drain diagnosis.
- User connects an Android phone via ADB (`adb devices`) or supplies an Android `dumpsys battery` + `dumpsys batterystats` dump.
- User asks why a phone loses charge overnight, overheats, throttles CPU/GPU (`CPMS`), stalls on storage (`Jetsam` / `cache_delete`), or wants an objective hardware health check before buying a used iPhone.

## Core Execution Workflow

1. **Always Prefer Read-Only Collection & Redacted Reporting:**
   - Never delete crash logs or device data (`erase=False` is enforced in `cellprobe_lib/ios_collector.py`).
   - Use `--redact` whenever saving reports intended for sharing or external LLM analysis.

2. **Run CellProbe CLI (`scripts/cellprobe.py`):**
   - **Auto-detect connected device:**
     ```bash
     python scripts/cellprobe.py scan --redact --out-ai diagnostic_ai.md --out-html diagnostic_report.html
     ```
   - **Live iPhone USB + deep sysdiagnose extraction:**
     ```bash
     python scripts/cellprobe.py ios --deep --redact --out-dir ./capture_ios --out-html iphone_report.html --out-ai iphone_ai.md
     ```
   - **Offline analysis (`sysdiagnose`, `CurrentPowerlog.PLSQL`, JSON, or Android dump):**
     ```bash
     python scripts/cellprobe.py analyze <target_path> --redact --format text
     ```

3. **Interpret the Verdict Without Masking:**
   - CellProbe uses **strict max-severity gating**:
     - `CRITICAL`: Lifetime UPO crashes `> 0`, unverified/non-genuine battery (`BatteryAuth == 0`), active CPMS throttling (`PPMStatsCPMSPowerReduction` / `.BGSQL` fallback), `WeightedRa >= 500 mOhm`, `health <= 75%` at `>= 1000` cycles, or `free_gb <= 1 GB`.
     - `HIGH`: `WeightedRa >= 350 mOhm`, `health < 80%` (or `battery_service` recommended), `cycles >= 1000`, frequent thermal pressure (`>= 40 C` or `>= 50` thermal events), or `free_gb < 5 GB`.
     - `MEDIUM`: `Auto-Lock == Never`, wakeup rate `>= 8.0 wakes/hr` (with `>= 1.0h` observation span), dynamic Lock-Screen Astronomy/Weather location polling, continuous background location apps (`>= 15m`), high wake-push channels, `ipsec`/`utun` VPN overhead, `'Hey Siri'` DSP wakes, or poor cellular signal (`>= 35%` at `<= 2 bars` or `>= 5` registration drops).

4. **Reproduce & Verify Included Tests:**
   - Verify with included synthetic fixtures:
     ```bash
     python scripts/cellprobe.py analyze examples/sample_ios_quick.json --redact --format text
     python scripts/cellprobe.py analyze examples/sample_android_dump.txt --format text
     ```
   - Run the unit test suite:
     ```bash
     python -m unittest discover -s tests -p "test*.py" -v
     ```

## Troubleshooting Live Collection

- **Windows `usbmuxd` Error 183 (`SavePairRecord`) on iOS:** Handled automatically in `cellprobe_lib/ios_collector.py` by reusing existing Apple Lockdown pair records (`autopair=False`). If pairing has never succeeded on the host PC, unlock the iPhone, tap **Trust**, and wait 5 seconds before running `cellprobe ios`.
- **Android `unauthorized`:** Unlock the Android device and accept the RSA USB Debugging prompt, then re-run `cellprobe android`.
