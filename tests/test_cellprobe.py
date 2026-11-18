#!/usr/bin/env python3
"""Unit tests for CellProbe core parsers, severity gating, HTML/AI renderers, and CLI."""

from __future__ import annotations

import contextlib
import io
import json
import plistlib
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True  # Keep __pycache__ clean during SkillSpector/QA runs

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cellprobe_lib.android_collector import parse_android_text_bundle  # noqa: E402
from cellprobe_lib.cli import main as cli_main  # noqa: E402
from cellprobe_lib.ios_collector import CollectorError, _validate_udid  # noqa: E402
from cellprobe_lib.ios_powerlog import _qident, _ro_connect, analyze_ios_artifacts, safe_extract_sysdiagnose  # noqa: E402
from cellprobe_lib.report_render import (  # noqa: E402
    Thresholds,
    evaluate_findings,
    redact_report,
    render_ai_bundle,
    render_html,
    render_json,
)

EXAMPLES_DIR = REPO_ROOT / "examples"
CLI_SCRIPT = REPO_ROOT / "scripts" / "cellprobe.py"


def _add_tar_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


class TestTarSecurityAndWindowsPaths(unittest.TestCase):
    def test_rejects_traversal_symlinks_reserved_names_and_sanitizes_colons(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            tgz_path = tmp_path / "sysdiagnose_test.TAR.GZ"
            extract_dir = tmp_path / "out"

            db_src = tmp_path / "CurrentPowerlog.PLSQL"
            conn = sqlite3.connect(db_src)
            conn.execute("CREATE TABLE t (x INTEGER)")
            conn.close()
            db_bytes = db_src.read_bytes()

            with tarfile.open(tgz_path, "w:gz") as tf:
                _add_tar_bytes(tf, "sysdiagnose_x/../evil.PLSQL", db_bytes)
                _add_tar_bytes(tf, "../../root_escape.PLSQL", db_bytes)
                _add_tar_bytes(tf, "sysdiagnose_x/logs/powerlogs/CON .PLSQL", db_bytes)
                _add_tar_bytes(tf, "._BatteryHealth.log", b"appledouble")
                _add_tar_bytes(tf, "sysdiagnose_x/logs/powerlogs/2026:11:18/OldPowerlog.PLSQL", db_bytes)
                _add_tar_bytes(tf, "sysdiagnose_x/logs/powerlogs/2026:11:18/CurrentPowerlog.PLSQL", db_bytes)
                _add_tar_bytes(tf, "sysdiagnose_x/logs/BatteryHealth/BatteryHealth.log", b"Maximum Capacity Percent = 86;\n")
                sym = tarfile.TarInfo("sysdiagnose_x/logs/powerlogs/link.PLSQL")
                sym.type = tarfile.SYMTYPE
                sym.linkname = "/tmp/outside_target"
                tf.addfile(sym)

            found = safe_extract_sysdiagnose(tgz_path, extract_dir)
            self.assertIn("plsql", found)
            self.assertIn("bhealth", found)
            self.assertEqual(found["plsql"].name, "CurrentPowerlog.PLSQL")
            self.assertNotIn(":", found["plsql"].resolve().relative_to(extract_dir.resolve()).as_posix())
            self.assertFalse((tmp_path / "evil.PLSQL").exists())
            self.assertFalse((extract_dir / "root_escape.PLSQL").exists())
            self.assertFalse((extract_dir / "logs" / "powerlogs" / "CON.PLSQL").exists())
            self.assertFalse((extract_dir / "logs" / "powerlogs" / "link.PLSQL").exists())

    def test_ro_connect_is_strictly_read_only_with_unicode_and_spaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = Path(tmp) / "User Folder" / "diag"
            db_dir.mkdir(parents=True)
            db_path = db_dir / "Power Log #1.PLSQL"
            wconn = sqlite3.connect(db_path)
            wconn.execute("CREATE TABLE items (n INTEGER)")
            wconn.execute("INSERT INTO items VALUES (42)")
            wconn.commit()
            wconn.close()

            ro = _ro_connect(db_path)
            try:
                self.assertEqual(ro.execute("SELECT n FROM items").fetchone()[0], 42)
                with self.assertRaises(sqlite3.OperationalError):
                    ro.execute("INSERT INTO items VALUES (99)")
            finally:
                ro.close()


class TestDynamicPowerlogParsing(unittest.TestCase):
    def test_parses_legacy_schema_open_cpms_bui_bhealth_and_qident(self) -> None:
        self.assertEqual(_qident('Col"Name'), '"Col""Name"')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pl_dir = root / "logs" / "powerlogs"
            bh_dir = root / "logs" / "BatteryHealth"
            pl_dir.mkdir(parents=True)
            bh_dir.mkdir(parents=True)
            pl_path = pl_dir / "CurrentPowerlog.PLSQL"
            epsql_path = pl_dir / "CurrentPowerlog.EPSQL"
            bgsql_path = pl_dir / "CurrentPowerlog.BGSQL"
            bui_path = pl_dir / "BatteryUISysdiagnose.plist"
            bh_path = bh_dir / "BatteryHealth.log"

            # Legacy PLSQL omitting IsCharging/AppleRawMaxCapacity + includes open-ended Sys1s_50+% CPMS col
            conn = sqlite3.connect(pl_path)
            conn.execute("CREATE TABLE PLStorageOperator_EventForward_TimeOffset (ID INTEGER PRIMARY KEY, system REAL)")
            conn.execute("INSERT INTO PLStorageOperator_EventForward_TimeOffset (system) VALUES (0.0)")
            conn.execute(
                "CREATE TABLE PLConfigAgent_EventNone_Config ("
                "ID INTEGER PRIMARY KEY, timestamp REAL, DeviceBootTime REAL, Device TEXT, InstalledSplat TEXT, "
                "Build TEXT, DeviceDiskSize INTEGER, RemainingDiskSpace INTEGER, AutoLockTime INTEGER)"
            )
            conn.execute(
                "INSERT INTO PLConfigAgent_EventNone_Config VALUES (1, 864000.0, 0.0, 'iPhone12,8', 'iOS 17.7', '21H16', 64, 4, 60)"
            )
            conn.execute(
                "CREATE TABLE PLBatteryAgent_EventNone_BatteryConfig ("
                "ID INTEGER PRIMARY KEY, CycleCount INTEGER, NominalChargeCapacity INTEGER, AppleRawMaxCapacity INTEGER, "
                "MaximumCapacityPercent INTEGER, ServiceOption INTEGER, batteryServiceFlags INTEGER, "
                "BatterySerialChanged INTEGER, WeightedRa INTEGER, RaTable_0 INTEGER, WeekMfd INTEGER, "
                "TotalOperatingTime INTEGER, LifetimeUPOCount INTEGER, MinimumPackVoltage INTEGER, "
                "MaximumDischargeCurrent INTEGER)"
            )
            conn.execute(
                "INSERT INTO PLBatteryAgent_EventNone_BatteryConfig VALUES "
                "(1, 0, 1800, 1790, 99, 0, 0, 0, 140, 150, 202601, 20, 0, 3650, 1200)"
            )
            conn.execute(
                "CREATE TABLE PLBatteryAgent_EventBackward_Battery ("
                "ID INTEGER PRIMARY KEY, timestamp REAL, Voltage INTEGER, Temperature REAL, InstantAmperage INTEGER)"
            )
            conn.execute("INSERT INTO PLBatteryAgent_EventBackward_Battery VALUES (1, 100.0, 3700, 0.0, -12)")
            conn.execute(
                'CREATE TABLE PLIOReportAgent_EventBackward_PPMStatsCPMSPowerReduction ("Sys1s_30-39%" REAL, "Sys1s_50-59%" REAL, "Sys1s_50+%" REAL)'
            )
            conn.execute("INSERT INTO PLIOReportAgent_EventBackward_PPMStatsCPMSPowerReduction VALUES (4.0, 2.5, 4.0)")
            conn.commit()
            conn.close()

            ep = sqlite3.connect(epsql_path)
            ep.execute("CREATE TABLE BatteryDataCollection_BDC_Once_3650_1 (ID INTEGER PRIMARY KEY, YWW TEXT, DesignCapacity INTEGER)")
            ep.execute("INSERT INTO BatteryDataCollection_BDC_Once_3650_1 VALUES (1, '601', 1821)")
            ep.execute("CREATE TABLE BatteryDataCollection_BDC_Weekly_1095_1 (ID INTEGER PRIMARY KEY, BatteryAuth INTEGER)")
            ep.execute("INSERT INTO BatteryDataCollection_BDC_Weekly_1095_1 VALUES (1, 0)")
            ep.commit()
            ep.close()

            bg = sqlite3.connect(bgsql_path)
            bg.execute(
                "CREATE TABLE BackgroundProcessing_SystemConditionsPowerManagement_30_1 "
                "(ID INTEGER PRIMARY KEY, ThermalPressure INTEGER, PeakPowerPressure INTEGER)"
            )
            for idx in range(1, 5):
                bg.execute("INSERT INTO BackgroundProcessing_SystemConditionsPowerManagement_30_1 VALUES (?, 1, 0)", (idx,))
            bg.commit()
            bg.close()

            bui_plist = {
                "Breakdown": {
                    "PLBatteryUIQueryRangeDayKey": {
                        "PLBatteryUITotalEnergyKey": 100,
                        "PLBatteryUIForegroundTimeKey": 3600,
                        "PLBatteryUIBackgroundTimeKey": 600,
                        "PLBatteryUIAppArrayKey": [
                            {
                                "PLBatteryUIAppNameKey": "Notes",
                                "PLBatteryUIAppBundleIDKey": "com.apple.mobilenotes",
                                "PLBatteryUIAppEnergyValueKey": 22,
                                "PLBatteryUIAppEnergyUsedKey": 120.0,
                                "PLBatteryUIAppForegroundRuntimeKey": 600,
                                "PLBatteryUIAppBackgroundRuntimeKey": 120,
                            }
                        ],
                    }
                }
            }
            bui_path.write_bytes(plistlib.dumps(bui_plist))
            bh_path.write_text("Maximum Capacity Percent = 84;\nBattery Service State = 0;\n", encoding="utf-8")

            report = analyze_ios_artifacts(root)
            self.assertEqual(report["platform"], "ios")
            self.assertEqual(report["hardware_battery"]["cycle_count"], 0)  # Falsy 0 preserved
            self.assertEqual(report["hardware_battery"]["max_temp_c"], 0.0)
            self.assertEqual(report["hardware_battery"]["ios_health_percent"], 84)
            self.assertEqual(report["hardware_battery"]["battery_auth"], 0)
            self.assertEqual(report["battery_ui"]["day"]["apps"][0]["name"], "Notes")
            cpms = report["hardware_battery"]["cpms_throttling"]
            self.assertTrue(cpms["detected"])
            self.assertAlmostEqual(cpms["reduction_10_49_sec"], 4.0, places=1)
            self.assertAlmostEqual(cpms["reduction_50_plus_sec"], 6.5, places=1)
            self.assertAlmostEqual(cpms["reduction_ge10_sec"], 10.5, places=1)
            self.assertGreaterEqual(cpms["max_reduction_pct"], 50)

            ev = evaluate_findings(report)
            self.assertEqual(ev["verdict"], "CRITICAL")


class TestSeverityGatingAndRenderers(unittest.TestCase):
    def test_thresholds_reject_invalid_values(self) -> None:
        for bad in (float("nan"), float("inf"), float("-inf"), 0.0, -5.0, 105.0, True):
            with self.assertRaises(ValueError):
                Thresholds(poor_signal_warn=bad)  # type: ignore[arg-type]
        for bad in (float("nan"), float("inf"), float("-inf"), 0.0, -5.0, False):
            with self.assertRaises(ValueError):
                Thresholds(max_wakes_per_hr=bad)  # type: ignore[arg-type]
        for bad_int in (0, 105, True):
            with self.assertRaises(ValueError):
                Thresholds(health_warn=bad_int)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            Thresholds(health_crit=85, health_warn=80)
        with self.assertRaises(ValueError):
            Thresholds(resistance_warn=600, resistance_crit=500)

    def test_service_flag_triggers_even_when_health_is_missing(self) -> None:
        rep = {
            "platform": "ios",
            "device": {"product_type": "iPhone13,1", "free_gb": 20},
            "hardware_battery": {"service_state": 1, "ios_health_percent": None, "cycle_count": None},
            "software_and_radio": {},
        }
        ev = evaluate_findings(rep)
        self.assertEqual(ev["hardware_verdict"], "HIGH")
        self.assertEqual(ev["findings"][0]["title"], "Battery Service Flagged by OS")

    def test_high_cycles_checked_even_when_health_above_80(self) -> None:
        raw = json.loads((EXAMPLES_DIR / "sample_ios_quick.json").read_text(encoding="utf-8"))
        raw["hardware_battery"].update(
            {
                "ios_health_percent": 86,
                "cycle_count": 1120,
                "weighted_ra_mohm": 200,
                "lifetime_upo_count": 0,
                "service_state": 0,
                "cpms_throttling": {"detected": False},
            }
        )
        raw["device"]["free_gb"] = 30
        ev = evaluate_findings(raw)
        self.assertEqual(ev["hardware_verdict"], "HIGH")
        self.assertTrue(any("High Battery Cycle Count" in f["title"] for f in ev["findings"]))

    def test_max_severity_never_masked_redaction_and_html_csp_xss(self) -> None:
        raw = json.loads((EXAMPLES_DIR / "sample_ios_quick.json").read_text(encoding="utf-8"))
        raw["device"]["product_type"] = '<script>alert("xss")</script>'
        raw["device"]["imei"] = "359999999999999"
        raw["collection_notes"] = [r"Pulled from C:\Users\alice\capture\sysdiag.tar.gz"]
        raw["battery_ui"]["week"]["apps"][0]["energy_pct"] = "bad"
        raw["battery_ui"]["week"]["apps"][0]["fg_min"] = '<img src=x onerror="alert(1)">'
        ev = evaluate_findings(raw)
        self.assertEqual(ev["verdict"], "CRITICAL")
        self.assertEqual(ev["hardware_verdict"], "CRITICAL")
        self.assertEqual(ev["software_storage_verdict"], "HIGH")

        redacted = redact_report(raw)
        self.assertEqual(redacted["device"]["udid"], "[REDACTED]")
        self.assertEqual(redacted["device"]["battery_serial"], "[REDACTED]")
        self.assertEqual(redacted["device"]["device_name"], "[REDACTED]")
        self.assertEqual(redacted["device"]["imei"], "[REDACTED]")
        self.assertNotIn("alice", redacted["collection_notes"][0])

        page = render_html(ev)
        self.assertIn('http-equiv="Content-Security-Policy"', page)
        self.assertNotIn('<script>alert("xss")</script>', page)
        self.assertNotIn('<img src=x onerror="alert(1)">', page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("&lt;img src=x", page)

        ai_md = render_ai_bundle(ev)
        self.assertLess(len(ai_md.encode("utf-8")), 12288)
        self.assertNotIn("SYNTHETICBATTSN01", ai_md)

        js = render_json(ev)
        self.assertEqual(json.loads(js)["verdict"], "CRITICAL")

    def test_udid_validator_rejects_traversal(self) -> None:
        self.assertEqual(_validate_udid("00008030-0011223344556677"), "00008030-0011223344556677")
        self.assertEqual(_validate_udid("a" * 40), "a" * 40)
        for bad in ("../other", "00008030/../../etc", "short"):
            with self.assertRaises(CollectorError):
                _validate_udid(bad)


class TestAndroidParser(unittest.TestCase):
    def test_parses_sample_android_dump_compact_durations_and_units(self) -> None:
        raw_txt = (EXAMPLES_DIR / "sample_android_dump.txt").read_text(encoding="utf-8")
        rep = parse_android_text_bundle(raw_txt)
        self.assertEqual(rep["platform"], "android")
        self.assertAlmostEqual(rep["device"]["free_gb"], 2.4, places=1)
        self.assertEqual(rep["hardware_battery"]["cycle_count"], 410)
        self.assertEqual(rep["hardware_battery"]["design_capacity_mah"], 4575)
        self.assertEqual(rep["hardware_battery"]["nominal_charge_capacity_mah"], 4120)
        self.assertAlmostEqual(rep["hardware_battery"]["capacity_retention_pct"], 90.1, places=1)
        self.assertAlmostEqual(rep["hardware_battery"]["actual_drain_mah"], 2210.0, places=1)
        self.assertEqual(rep["software_and_radio"]["cellular"]["poor_signal_pct"], 38.0)

        # Compact multi-unit duration + negative temp + uV voltage + Max charging voltage guard
        compact = (
            "Current Battery Service state:\n"
            "  Max charging voltage: 5000000\n"
            "  voltage: 3820000\n"
            "  temperature: -50\n"
            "Screen on: +1d2h30m0s500ms (20%) 4x\n"
        )
        c_rep = parse_android_text_bundle(compact)
        self.assertEqual(c_rep["hardware_battery"]["voltage_min_mv"], 3820)
        self.assertEqual(c_rep["hardware_battery"]["max_temp_c"], -5.0)
        self.assertAlmostEqual(c_rep["usage"]["avg_screen_on_hours_per_day"], 26.5, places=2)

        ev = evaluate_findings(rep)
        self.assertEqual(ev["verdict"], "HIGH")


class TestCLIContract(unittest.TestCase):
    def test_cli_exit_codes_output_files_utf16_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            html_out = tpath / "dash.html"
            json_out = tpath / "rep.json"
            ai_out = tpath / "brief.md"
            buf_out, buf_err = io.StringIO(), io.StringIO()

            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                rc_ok = cli_main(
                    [
                        "analyze",
                        str(EXAMPLES_DIR / "sample_ios_quick.json"),
                        "--redact",
                        "--format",
                        "text",
                        "--out-html",
                        str(html_out),
                        "--out-json",
                        str(json_out),
                        "--out-ai",
                        str(ai_out),
                    ]
                )
            self.assertEqual(rc_ok, 0)
            saved = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(saved["device"]["udid"], "[REDACTED]")
            self.assertIn("source_sha256", saved)
            self.assertTrue(html_out.exists() and ai_out.exists())

            # Windows PowerShell UTF-16 LE BOM redirected dumpsys file must analyze cleanly
            utf16_dump = tpath / "ps_dump.txt"
            utf16_dump.write_text((EXAMPLES_DIR / "sample_android_dump.txt").read_text(encoding="utf-8"), encoding="utf-16")
            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                self.assertEqual(cli_main(["analyze", str(utf16_dump), "--format", "json"]), 0)

            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                self.assertEqual(
                    cli_main(["analyze", str(EXAMPLES_DIR / "sample_ios_quick.json"), "--fail-on", "CRITICAL", "--format", "json"]),
                    1,
                )
                self.assertEqual(
                    cli_main(["analyze", str(EXAMPLES_DIR / "sample_android_dump.txt"), "--fail-on", "CRITICAL", "--format", "text"]),
                    0,
                )
                self.assertEqual(
                    cli_main(["analyze", str(EXAMPLES_DIR / "sample_android_dump.txt"), "--fail-on", "HIGH", "--format", "text"]),
                    1,
                )
                self.assertEqual(cli_main(["analyze", str(tpath / "does_not_exist.tar.gz")]), 2)

                empty_txt = tpath / "empty.txt"
                empty_txt.write_text("", encoding="utf-8")
                self.assertEqual(cli_main(["analyze", str(empty_txt)]), 2)

                nan_json = tpath / "nan.json"
                nan_json.write_text('{"platform":"ios","hardware_battery":{"max_temp_c":NaN}}', encoding="utf-8")
                self.assertEqual(cli_main(["analyze", str(nan_json)]), 2)

                zero_sig = tpath / "zero_sig.json"
                zero_sig.write_text(
                    '{"platform":"ios","device":{},"hardware_battery":{},"software_and_radio":{"cellular":{"poor_signal_pct":0.0}}}',
                    encoding="utf-8",
                )
                with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                    self.assertEqual(cli_main(["analyze", str(zero_sig), "--format", "json"]), 0)

                corrupt_tgz = tpath / "broken.tar.gz"
                corrupt_tgz.write_bytes(b"not-a-valid-gzip-archive")
                self.assertEqual(cli_main(["analyze", str(corrupt_tgz)]), 2)

    def test_subprocess_help_and_no_traceback_on_bad_flags_or_nan(self) -> None:
        proc_help = subprocess.run(
            [sys.executable, str(CLI_SCRIPT), "--help"],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_help.returncode, 0)

        for extra in (
            ["--non-existent-qa-flag-xyz"],
            ["analyze", str(EXAMPLES_DIR / "sample_ios_quick.json"), "--poor-signal-warn", "nan"],
        ):
            proc = subprocess.run(
                [sys.executable, str(CLI_SCRIPT), *extra],
                shell=False,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn("Traceback (most recent call last)", proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
