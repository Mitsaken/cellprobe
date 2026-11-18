# CellProbe Live Output Walkthrough

Every command and output below was executed directly against the synthetic sample fixtures included in `examples/`.

---

## 1. Analyze an iOS Diagnostic Snapshot (Redacted Text Report)

```bash
python scripts/cellprobe.py analyze examples/sample_ios_quick.json --redact --format text
```

Output (exit code `0`):

```text
==============================================================================
CELLPROBE DIAGNOSTIC REPORT  |  Verdict: [CRITICAL]
Hardware: CRITICAL  |  Software/Storage/Radio: HIGH
==============================================================================
Device      : iPhone12,8 (D79AP) | iOS 18.6 (Build 22G100)
Storage     : Free 2 GB / 64 GB  |  Auto-Lock Never: True  |  Uptime: 14.2d
Battery HW  : Cycles=1180 | OS Health=73% | Cap=1240/1821 mAh (68.1%)
Impedance   : WeightedRa=542 mOhm (RaTable max=620) | MinVolt=3290 mV | MaxTemp=41.2 C
CPMS / Auth : Throttling=True (max -30%) | GenuineAuth=1 | UPO=2
Usage / Idle: Avg ScreenOn=4.3h/d | IdleCurrent=-8.4 mA | 24h Wakes=284

FINDINGS (12):
  1. [CRITICAL] (Hardware) Unexpected Power-Off (UPO) Crashes Detected
     Why   : LifetimeUPOCount = 2. Battery voltage sag triggered abrupt shutdowns.
     Action: Replace the battery immediately to restore peak voltage stability.
  2. [CRITICAL] (Hardware) Active CPMS Power / CPU Throttling Engaged
     Why   : System reduced peak power up to 30% (84.5s under >=10% reduction; 4 peak-power pressure transitions).
     Action: Plan battery service; high impedance or voltage/thermal limits forced CPMS power capping.
  3. [CRITICAL] (Hardware) Severe Internal Resistance (Cell Impedance)
     Why   : WeightedRa = 542 mOhm (>= 500 mOhm critical threshold). Causes sharp voltage sag under load.
     Action: Plan battery replacement; high impedance drives heat and premature % drops.
  4. [CRITICAL] (Hardware) Severe Battery Degradation Indicators Detected
     Why   : Battery Health = 73% (<= 75%), CycleCount = 1180, Retention = 68.1% (1240/1821 mAh).
     Action: Battery service or cell replacement recommended to restore full runtime stability.
  5. [HIGH] (Thermal) Frequent Elevated Thermal Pressure
     Why   : Peak observed temp = 41.2 C, high-temp samples (>=39 C) = 12, thermal pressure events = 18.
     Action: Avoid fast charging while running heavy video/social apps; degraded cells generate extra I^2*R heat.
  6. [HIGH] (Storage) Low Free Storage Space
     Why   : Only 2 GB free (< 5 GB). May trigger background cache cleanup churn.
     Action: Clear >= 5-10 GB of cached media/downloads.
  7. [MEDIUM] (System) Auto-Lock Set to 'Never'
     Why   : Display Auto-Lock is disabled (Never), risking unattended screen-on drain.
     Action: Set Settings -> Display & Brightness -> Auto-Lock to 1 Minute (or 30 Seconds).
  8. [MEDIUM] (Wakeups) High Standby / Periodic Wakeup Rate
     Why   : 284 wakes in ~24.0h (11.8 wakes/hr >= 8.0/hr threshold).
     Action: Trim wake-push apps, lock-screen dynamic wallpapers, and Background App Refresh.
  9. [MEDIUM] (Software) Dynamic Astronomy / Weather Lock-Screen Polling Location
     Why   : Lock screen poster queried Location 32 times in Powerlog.
     Action: Switch Lock Screen wallpaper to a static Photo/Color instead of Astronomy/Weather.
  10. [MEDIUM] (Location) Apps Polling Location Continuously in Background
     Why   : BackgroundLocationTime detected: com.example.weatherwidget (21.5m).
     Action: Set Location access from 'Always' to 'While Using the App' for non-tracking apps.
  11. [MEDIUM] (Notifications) Frequent High-Priority Push Wakeups
     Why   : 24h wake-triggering pushes: com.example.social (46x/wwan).
     Action: Enable Scheduled Summary or mute non-urgent channels for heavy push apps.
  12. [MEDIUM] (Cellular) Weak Cellular Signal / Tower Re-Registration Drain
     Why   : 46.0% of cellular time spent at <=2 signal bars; 7 EmergencyOnly/NotRegistered drops.
     Action: Prefer Wi-Fi Calling indoors; lock Voice & Data to LTE (avoid 5G On) in low-coverage areas.

TOP ENERGY CONSUMERS (7-Day Sum):
  - ExampleSocial (com.example.social): 41% | fg=420.0m | bg=310.0m
==============================================================================
```

---

## 2. Analyze an Android `dumpsys` Text Bundle

```bash
python scripts/cellprobe.py analyze examples/sample_android_dump.txt --format text
```

Output (exit code `0`):

```text
==============================================================================
CELLPROBE DIAGNOSTIC REPORT  |  Verdict: [HIGH]
Hardware: HEALTHY  |  Software/Storage/Radio: HIGH
==============================================================================
Device      : Pixel 8 Sample (Google) | Android 15 (Build AP3A.241005.015)
Storage     : Free 2.4 GB / 106.8 GB  |  Auto-Lock Never: False  |  Uptime: N/A
Battery HW  : Cycles=410 | OS Health=N/A | Cap=4120/4575 mAh (90.1%)
Impedance   : WeightedRa=N/A (RaTable max=N/A) | MinVolt=3785 mV | MaxTemp=34.2 C
CPMS / Auth : Throttling=False (max -0%) | GenuineAuth=N/A | UPO=0
Usage / Idle: Avg ScreenOn=4.54h/d | IdleCurrent=N/A | 24h Wakes=N/A

FINDINGS (2):
  1. [HIGH] (Storage) Low Free Storage Space
     Why   : Only 2.4 GB free (< 5 GB). May trigger background cache cleanup churn.
     Action: Clear >= 5-10 GB of cached media/downloads.
  2. [MEDIUM] (Cellular) Weak Cellular Signal / Tower Re-Registration Drain
     Why   : 38.0% of cellular time spent at <=2 signal bars; 0 EmergencyOnly/NotRegistered drops.
     Action: Prefer Wi-Fi Calling indoors; lock Voice & Data to LTE (avoid 5G On) in low-coverage areas.

TOP ENERGY CONSUMERS (24h):
  - u0a214 (u0a214): 54% | fg=0.0m | bg=0.0m
  - u0a102 (u0a102): 31% | fg=0.0m | bg=0.0m
  - 1000 (1000): 15% | fg=0.0m | bg=0.0m
==============================================================================
```

---

## 3. Severity Gating in Automation (`--fail-on`)

```bash
python scripts/cellprobe.py analyze examples/sample_ios_quick.json --fail-on CRITICAL --format text
# Exit code: 1 (CRITICAL verdict matched --fail-on CRITICAL)

python scripts/cellprobe.py analyze examples/sample_android_dump.txt --fail-on CRITICAL --format text
# Exit code: 0 (HIGH verdict < CRITICAL)
```

---

## 4. Run Unit Test Suite

```bash
python -m unittest discover -s tests -p "test*.py" -v
```

Output (`Ran 11 tests ... OK`, exit code `0`):

```text
test_parses_sample_android_dump_compact_durations_and_units (test_cellprobe.TestAndroidParser.test_parses_sample_android_dump_compact_durations_and_units) ... ok
test_cli_exit_codes_output_files_utf16_and_validation (test_cellprobe.TestCLIContract.test_cli_exit_codes_output_files_utf16_and_validation) ... ok
test_subprocess_help_and_no_traceback_on_bad_flags_or_nan (test_cellprobe.TestCLIContract.test_subprocess_help_and_no_traceback_on_bad_flags_or_nan) ... ok
test_parses_legacy_schema_open_cpms_bui_bhealth_and_qident (test_cellprobe.TestDynamicPowerlogParsing.test_parses_legacy_schema_open_cpms_bui_bhealth_and_qident) ... ok
test_high_cycles_checked_even_when_health_above_80 (test_cellprobe.TestSeverityGatingAndRenderers.test_high_cycles_checked_even_when_health_above_80) ... ok
test_max_severity_never_masked_redaction_and_html_csp_xss (test_cellprobe.TestSeverityGatingAndRenderers.test_max_severity_never_masked_redaction_and_html_csp_xss) ... ok
test_service_flag_triggers_even_when_health_is_missing (test_cellprobe.TestSeverityGatingAndRenderers.test_service_flag_triggers_even_when_health_is_missing) ... ok
test_thresholds_reject_invalid_values (test_cellprobe.TestSeverityGatingAndRenderers.test_thresholds_reject_invalid_values) ... ok
test_udid_validator_rejects_traversal (test_cellprobe.TestSeverityGatingAndRenderers.test_udid_validator_rejects_traversal) ... ok
test_rejects_traversal_symlinks_reserved_names_and_sanitizes_colons (test_cellprobe.TestTarSecurityAndWindowsPaths.test_rejects_traversal_symlinks_reserved_names_and_sanitizes_colons) ... ok
test_ro_connect_is_strictly_read_only_with_unicode_and_spaces (test_cellprobe.TestTarSecurityAndWindowsPaths.test_ro_connect_is_strictly_read_only_with_unicode_and_spaces) ... ok
```
