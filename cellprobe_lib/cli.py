#!/usr/bin/env python3
"""
CellProbe CLI Entrypoint (Pure Python Stdlib + Optional pymobiledevice3 / adb).

Provides clean exit codes:
  0 = Success (and below --fail-on threshold)
  1 = Findings met or exceeded --fail-on threshold
  2 = Usage / input / device connection error (never emits raw tracebacks)
"""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import Any, Sequence
from xml.parsers.expat import ExpatError

from cellprobe_lib import __version__
from cellprobe_lib.android_collector import (
    AndroidCollectorError,
    collect_android_live,
    list_android_devices,
    parse_android_text_bundle,
)
from cellprobe_lib.ios_collector import CollectorError, collect_ios_live, list_ios_usb_devices
from cellprobe_lib.ios_powerlog import analyze_ios_artifacts, file_sha256
from cellprobe_lib.report_render import (
    SEVERITY_ORDER,
    Thresholds,
    evaluate_findings,
    redact_report,
    render_ai_bundle,
    render_html,
    render_json,
    render_text,
)


def _positive_int(raw: str) -> int:
    try:
        val = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected integer, got {raw!r}.") from exc
    if val <= 0:
        raise argparse.ArgumentTypeError(f"Value must be > 0, got {val}.")
    return val


def _positive_finite_float(raw: str) -> float:
    try:
        val = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected number, got {raw!r}.") from exc
    if not math.isfinite(val) or val <= 0.0:
        raise argparse.ArgumentTypeError(f"Value must be a finite number > 0, got {raw!r}.")
    return val


def _add_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json", "ai", "html"),
        default="text",
        help="Primary stdout output format (default: text).",
    )
    parser.add_argument("--out-json", type=Path, help="Optional path to write JSON report.")
    parser.add_argument("--out-ai", type=Path, help="Optional path to write compact AI Markdown bundle.")
    parser.add_argument("--out-html", type=Path, help="Optional path to write self-contained HTML dashboard.")
    parser.add_argument("--redact", action="store_true", help="Strip UDIDs, serial numbers, and custom device names.")
    parser.add_argument(
        "--fail-on",
        choices=("NONE", "MEDIUM", "HIGH", "CRITICAL"),
        default="NONE",
        help="Exit with code 1 if overall severity meets or exceeds this level (default: NONE).",
    )
    parser.add_argument("--health-warn", type=_positive_int, default=80, help="Battery health warning threshold %% (default: 80).")
    parser.add_argument("--health-crit", type=_positive_int, default=75, help="Severe battery health threshold %% combined with cycles (default: 75).")
    parser.add_argument("--cycles-high", type=_positive_int, default=1000, help="High cycle count threshold (default: 1000).")
    parser.add_argument("--resistance-warn", type=_positive_int, default=350, help="WeightedRa warning mOhm (default: 350).")
    parser.add_argument("--resistance-crit", type=_positive_int, default=500, help="WeightedRa critical mOhm (default: 500).")
    parser.add_argument("--min-free-gb", type=_positive_int, default=5, help="Low free storage threshold GB (default: 5).")
    parser.add_argument("--poor-signal-warn", type=_positive_finite_float, default=35.0, help="Poor cellular signal %% warning (default: 35.0).")
    parser.add_argument("--max-wakes-per-hr", type=_positive_finite_float, default=8.0, help="Standby wake rate warning wakes/hr (default: 8.0).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cellprobe",
        description="Read-only iOS & Android battery, powerlog, thermal & radio forensic CLI.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Auto-detect connected iOS (USB) and/or Android (ADB) devices and diagnose.")
    p_scan.add_argument("--platform", choices=("auto", "ios", "android"), default="auto", help="Force target platform (default: auto).")
    p_scan.add_argument("--udid", help="Specific iOS UDID if multiple iPhones are attached.")
    p_scan.add_argument("--serial", help="Specific Android ADB serial if multiple devices are attached.")
    p_scan.add_argument("--deep", action="store_true", help="Pull latest on-device iOS sysdiagnose archive for full Powerlog SQLite audit.")
    p_scan.add_argument("--out-dir", type=Path, help="Directory to store pulled read-only artifacts.")
    _add_common_flags(p_scan)

    p_ios = sub.add_parser("ios", help="Run live read-only USB diagnostics on an attached iPhone/iPad.")
    p_ios.add_argument("--udid", help="Specific iOS UDID if multiple devices are attached.")
    p_ios.add_argument("--deep", action="store_true", help="Pull latest completed sysdiagnose archive (Powerlog/BatteryConfig/CPMS).")
    p_ios.add_argument("--out-dir", type=Path, help="Directory to store pulled sysdiagnose/Analytics files.")
    _add_common_flags(p_ios)

    p_and = sub.add_parser("android", help="Run live read-only ADB diagnostics on an attached Android device.")
    p_and.add_argument("--serial", help="Specific Android ADB serial.")
    p_and.add_argument("--out-dir", type=Path, help="Directory to save raw dumpsys text bundle.")
    _add_common_flags(p_and)

    p_ana = sub.add_parser(
        "analyze",
        help="Offline analysis of sysdiagnose .tar.gz/.tgz, CurrentPowerlog.PLSQL, extracted dir, .json fixture, or Android dumpsys .txt.",
    )
    p_ana.add_argument("target", type=Path, help="Path to sysdiagnose archive, Powerlog DB, extracted folder, JSON fixture, or Android dump.")
    p_ana.add_argument("--out-dir", type=Path, help="Optional persistent directory for archive extraction.")
    _add_common_flags(p_ana)

    return parser


def _reject_bad_json_const(token: str) -> Any:
    raise ValueError(f"Non-finite JSON constant not allowed: {token}")


def _read_text_auto_encoding(path: Path, max_bytes: int | None = None) -> str:
    with path.open("rb") as fh:
        raw_bytes = fh.read(max_bytes) if max_bytes is not None else fh.read()
    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw_bytes.decode("utf-16", errors="replace")
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        return raw_bytes.decode("utf-8-sig", errors="replace")
    # Handle BOM-less UTF-16 LE often seen in redirected Windows console dumps
    if len(raw_bytes) >= 4 and b"\x00" in raw_bytes[:64] and raw_bytes[1:2] == b"\x00":
        return raw_bytes.decode("utf-16-le", errors="replace")
    return raw_bytes.decode("utf-8", errors="replace")


def _looks_like_android_dump(path: Path) -> bool:
    try:
        head = _read_text_auto_encoding(path, max_bytes=65536)
    except OSError:
        return False
    markers = (
        "Current Battery Service state",
        "=== BATTERY ===",
        "=== GETPROP ===",
        "Battery History (",
        "Estimated power use (mAh)",
        "mSavedBatteryAsoc:",
        "mBatteryCycleCount:",
        "Cellular signal levels:",
    )
    return any(m in head for m in markers)


def _validate_populated_report(report: dict[str, Any], target: Path) -> None:
    hw = report.get("hardware_battery")
    dev = report.get("device")
    bui = report.get("battery_ui")
    sw = report.get("software_and_radio")
    usage = report.get("usage")
    if not isinstance(hw, dict) or not isinstance(dev, dict):
        raise ValueError(f"Invalid CellProbe telemetry structure in: {target}")

    day_apps = ((bui.get("day") or {}).get("apps") if isinstance(bui, dict) else None) or []
    week_apps = ((bui.get("week") or {}).get("apps") if isinstance(bui, dict) else None) or []
    has_apps = bool(day_apps or week_apps)
    has_sw = isinstance(sw, dict) and any(
        [
            bool(sw.get("root_nodes_24h")),
            bool(sw.get("wake_reasons_24h")),
            bool(sw.get("pushes_24h")),
            bool(sw.get("location_clients")),
            (sw.get("cellular") or {}).get("poor_signal_pct") is not None,
        ]
    )
    has_usage = isinstance(usage, dict) and any(
        usage.get(k) is not None for k in ("avg_screen_on_hours_per_day", "time_on_batt_hours", "time_on_battery_hours", "days_observed")
    )
    has_dev_model = bool(dev.get("hardware_model")) or (report.get("platform") == "ios" and bool(dev.get("product_type")))
    has_signal = any(
        [
            hw.get("cycle_count") is not None,
            hw.get("ios_health_percent") is not None,
            hw.get("design_capacity_mah") is not None,
            hw.get("nominal_charge_capacity_mah") is not None,
            hw.get("weighted_ra_mohm") is not None,
            hw.get("voltage_min_mv") is not None,
            dev.get("free_gb") is not None,
            has_dev_model,
            has_apps,
            has_sw,
            has_usage,
        ]
    )
    if not has_signal:
        raise ValueError(f"No supported iOS or Android battery/powerlog telemetry found in: {target}")


def _run_analyze(target: Path, out_dir: Path | None) -> dict[str, Any]:
    if not target.exists():
        raise FileNotFoundError(f"Input path does not exist: {target}")

    if target.is_file() and target.name.lower().endswith(".json"):
        try:
            raw = json.loads(target.read_text(encoding="utf-8"), parse_constant=_reject_bad_json_const)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON input ({target}): {exc}") from exc
        if not isinstance(raw, dict) or "platform" not in raw or "hardware_battery" not in raw:
            raise ValueError(f"Unsupported JSON schema in {target}: expected CellProbe report keys 'platform' and 'hardware_battery'.")
        _validate_populated_report(raw, target)
        if "source_sha256" not in raw:
            sha = file_sha256(target)
            if sha:
                raw["source_sha256"] = sha
        return raw

    if target.is_file() and _looks_like_android_dump(target):
        raw_txt = _read_text_auto_encoding(target)
        rep = parse_android_text_bundle(raw_txt)
        _validate_populated_report(rep, target)
        sha = file_sha256(target)
        if sha:
            rep["source_sha256"] = sha
        return rep

    if out_dir is not None:
        rep = analyze_ios_artifacts(target, work_dir=out_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="cellprobe_") as tmp_dir:
            rep = analyze_ios_artifacts(target, work_dir=Path(tmp_dir))
    _validate_populated_report(rep, target)
    return rep


def _run_scan(args: argparse.Namespace) -> dict[str, Any]:
    plat = args.platform
    if plat == "ios":
        return collect_ios_live(udid=args.udid, out_dir=args.out_dir, deep=args.deep)
    if plat == "android":
        return collect_android_live(serial=args.serial, out_dir=args.out_dir)

    ios_err: str | None = None
    and_err: str | None = None
    ios_devs: list[dict[str, Any]] = []
    and_devs: list[dict[str, str]] = []

    if not args.serial:
        try:
            ios_devs = list_ios_usb_devices()
        except CollectorError as exc:
            ios_err = str(exc)

    if not args.udid:
        try:
            and_devs = [d for d in list_android_devices() if d["state"] == "device"]
        except AndroidCollectorError as exc:
            and_err = str(exc)

    if ios_devs and not and_devs:
        return collect_ios_live(udid=args.udid, out_dir=args.out_dir, deep=args.deep)
    if and_devs and not ios_devs:
        return collect_android_live(serial=args.serial, out_dir=args.out_dir)
    if ios_devs and and_devs:
        raise CollectorError(
            "Both iOS and Android devices are connected simultaneously. "
            "Use 'cellprobe ios' or 'cellprobe android' (or pass --platform ios|android)."
        )

    hints = [m for m in (ios_err, and_err) if m]
    detail = f" Details: {' | '.join(hints)}" if hints else ""
    raise CollectorError(
        "No connected iOS USB or ADB-authorized Android devices found." + detail
    )


def _render_and_write(evaluated: dict[str, Any], args: argparse.Namespace) -> None:
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(render_json(evaluated), encoding="utf-8")
    if args.out_ai is not None:
        args.out_ai.parent.mkdir(parents=True, exist_ok=True)
        args.out_ai.write_text(render_ai_bundle(evaluated), encoding="utf-8")
    if args.out_html is not None:
        args.out_html.parent.mkdir(parents=True, exist_ok=True)
        args.out_html.write_text(render_html(evaluated), encoding="utf-8")

    fmt = args.format
    if fmt == "json":
        out = render_json(evaluated)
    elif fmt == "ai":
        out = render_ai_bundle(evaluated)
    elif fmt == "html":
        out = render_html(evaluated)
    else:
        out = render_text(evaluated)
    print(out)


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        thresholds = Thresholds(
            health_warn=args.health_warn,
            health_crit=args.health_crit,
            cycles_high=args.cycles_high,
            resistance_warn=args.resistance_warn,
            resistance_crit=args.resistance_crit,
            min_free_gb=args.min_free_gb,
            poor_signal_warn=args.poor_signal_warn,
            max_wakes_per_hr=args.max_wakes_per_hr,
        )

        if args.command == "analyze":
            raw_report = _run_analyze(args.target, args.out_dir)
        elif args.command == "ios":
            raw_report = collect_ios_live(udid=args.udid, out_dir=args.out_dir, deep=args.deep)
        elif args.command == "android":
            raw_report = collect_android_live(serial=args.serial, out_dir=args.out_dir)
        elif args.command == "scan":
            raw_report = _run_scan(args)
        else:
            print(f"Error: Unknown command {args.command!r}", file=sys.stderr)
            return 2

        if args.redact:
            raw_report = redact_report(raw_report)

        evaluated = evaluate_findings(raw_report, thresholds=thresholds)
        _render_and_write(evaluated, args)

        fail_lvl = args.fail_on
        if fail_lvl != "NONE":
            sev = evaluated.get("verdict")
            if sev not in SEVERITY_ORDER:
                raise ValueError(f"Unknown verdict severity: {sev!r}")
            if SEVERITY_ORDER[sev] >= SEVERITY_ORDER[fail_lvl]:
                return 1
        return 0
    except (
        CollectorError,
        AndroidCollectorError,
        FileNotFoundError,
        ValueError,
        OSError,
        tarfile.TarError,
        sqlite3.Error,
        ExpatError,
        EOFError,
        zlib.error,
        OverflowError,
        UnicodeDecodeError,
        TypeError,
        AttributeError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
