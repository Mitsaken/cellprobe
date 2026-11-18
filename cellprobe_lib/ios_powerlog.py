#!/usr/bin/env python3
"""
CellProbe iOS Sysdiagnose & Powerlog Analyzer (Pure Python Stdlib).

Safely extracts and analyzes Apple sysdiagnose archives (.tar.gz), extracted
directories, or standalone .PLSQL/.EPSQL/.BGSQL/.plist/.ips telemetry with
dynamic SQLite schema introspection across iOS 17/18/26/27+.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import plistlib
import re
import sqlite3
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

MAX_TAR_MEMBER_BYTES = 150 * 1024 * 1024  # 150 MB cap per extracted diagnostic file
MAX_TAR_MEMBERS = 400
MAX_TOTAL_EXTRACT_BYTES = 512 * 1024 * 1024  # 512 MB cumulative cap per archive
_WIN_RESERVED_STEMS = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
_WIN_BAD_CHARS_RE = re.compile(r'[<>:"|?*\x00-\x1f]')


def file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _reject_bad_json_const(token: str) -> Any:
    raise ValueError(f"Non-finite JSON constant not allowed: {token}")


def _first_not_none(*vals: Any) -> Any:
    for v in vals:
        if v is not None:
            return v
    return None


def _qident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _safe_float(val: Any, default: float | None = None) -> float | None:
    if val is None or isinstance(val, bool):
        return default
    try:
        f = float(val)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_int(val: Any, default: int | None = None) -> int | None:
    f = _safe_float(val)
    return int(round(f)) if f is not None else default


def _apple_or_unix_ts(ts: Any) -> float | None:
    f = _safe_float(ts)
    if f is None:
        return None
    if 500_000_000 < f < 1_000_000_000:
        f += 978_307_200.0
    return f if 1_200_000_000 < f < 2_600_000_000 else None


def fmt_ts(ts: Any, tz_hours: float = 0.0) -> str | None:
    unix = _apple_or_unix_ts(ts)
    if unix is None:
        return None
    try:
        tz = timezone.utc if tz_hours == 0.0 else timezone(timedelta(hours=tz_hours))
        dt = datetime.fromtimestamp(unix, tz=tz)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if tz_hours == 0.0 else dt.isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _ro_connect(db_path: Path) -> sqlite3.Connection:
    resolved = db_path.resolve()
    base_uri = resolved.as_uri()
    last_exc: sqlite3.Error | None = None
    for uri in (f"{base_uri}?mode=ro", f"{base_uri}?mode=ro&immutable=1"):
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            conn.execute("PRAGMA query_only = ON;")
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1;").fetchone()
            return conn
        except sqlite3.Error as exc:
            last_exc = exc
            if conn is not None:
                conn.close()
    raise last_exc or sqlite3.OperationalError(f"Cannot open SQLite read-only: {resolved}")


def _sanitize_member_relpath(raw_name: str) -> Path | None:
    if not raw_name or raw_name.startswith(("/", "\\")):
        return None
    cleaned = raw_name.replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    parts = [p for p in cleaned.split("/") if p]
    if not parts:
        return None
    if any(p in ("..", ".") for p in parts):
        return None
    # Reject drive letters before colon replacement
    if parts[0].endswith(":") or (len(parts[0]) >= 2 and parts[0][1] == ":"):
        return None
    # Strip top archive wrapper directory if present (sysdiagnose_.../)
    if len(parts) > 1 and parts[0].startswith("sysdiagnose_"):
        parts = parts[1:]
    safe_parts: list[str] = []
    for p in parts:
        # Windows disallows ':' and '< > " | ? *' and strips trailing spaces/dots
        sp = p.replace(":", "_").rstrip(" .")
        if not sp or sp in ("..", ".") or _WIN_BAD_CHARS_RE.search(sp):
            return None
        stem = sp.split(".", 1)[0].upper()
        if stem in _WIN_RESERVED_STEMS:
            return None
        safe_parts.append(sp)
    return Path(*safe_parts)


def _prefer_db_path(current: Path | None, candidate: Path) -> Path:
    if current is None:
        return candidate
    if "currentpowerlog" in candidate.name.lower() and "currentpowerlog" not in current.name.lower():
        return candidate
    return current


def safe_extract_sysdiagnose(tar_path: Path, dest_dir: Path) -> dict[str, Any]:
    """Stream-extract only battery/powerlog diagnostic files safely (Win11-safe)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    found: dict[str, Any] = {"bdc_daily": [], "bdc_weekly": [], "analytics": []}
    resolved_root = dest_dir.resolve()
    extracted_files = 0
    total_bytes = 0

    with tarfile.open(tar_path, "r:gz") as tf:
        for m in tf:
            if m.issym() or m.islnk() or not m.isfile():
                continue
            bn = os.path.basename(m.name)
            if bn.startswith("._"):
                continue
            low = m.name.lower()
            is_wanted = (
                low.endswith(".plsql")
                or low.endswith(".epsql")
                or low.endswith(".bgsql")
                or bn in ("BatteryUISysdiagnose.plist", "BatteryUI.plist", "com.apple.powerd.bdc.plist")
                or (bn == "BatteryHealth.log" and "batteryhealth" in low)
                or ("batterybdc" in low and ("bdc_daily_" in low or "bdc_weekly_" in low) and low.endswith(".csv"))
                or (bn.lower().startswith("analytics-") and (low.endswith(".ips") or low.endswith(".ips.synced")))
            )
            if not is_wanted:
                continue
            if m.size > MAX_TAR_MEMBER_BYTES or m.size < 0:
                continue
            if extracted_files >= MAX_TAR_MEMBERS or (total_bytes + m.size) > MAX_TOTAL_EXTRACT_BYTES:
                continue

            rel = _sanitize_member_relpath(m.name)
            if rel is None:
                continue
            dst = (dest_dir / rel).resolve()
            if resolved_root not in dst.parents and dst != resolved_root:
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)

            src = tf.extractfile(m)
            if src is None:
                continue
            written = 0
            with src, open(dst, "wb") as out_f:
                remaining = MAX_TAR_MEMBER_BYTES
                while True:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    if (total_bytes + written + len(chunk)) > MAX_TOTAL_EXTRACT_BYTES:
                        raise ValueError("Archive exceeds cumulative 512 MB extraction limit.")
                    out_f.write(chunk)
                    written += len(chunk)
                    remaining -= len(chunk)
                    if remaining <= 0:
                        break
            extracted_files += 1
            total_bytes += written

            if low.endswith(".plsql"):
                found["plsql"] = _prefer_db_path(found.get("plsql"), dst)
            elif low.endswith(".epsql"):
                found["epsql"] = _prefer_db_path(found.get("epsql"), dst)
            elif low.endswith(".bgsql"):
                found["bgsql"] = _prefer_db_path(found.get("bgsql"), dst)
            elif bn == "BatteryUISysdiagnose.plist":
                found["bui_sd"] = dst
            elif bn == "BatteryUI.plist":
                found["bui"] = dst
            elif bn == "BatteryHealth.log":
                found["bhealth"] = dst
            elif bn == "com.apple.powerd.bdc.plist":
                found["bdc_plist"] = dst
            elif "bdc_daily_" in low:
                found["bdc_daily"].append(dst)
            elif "bdc_weekly_" in low:
                found["bdc_weekly"].append(dst)
            elif bn.lower().startswith("analytics-"):
                found["analytics"].append(dst)

    return found


def discover_extracted_dir(root: Path) -> dict[str, Any]:
    found: dict[str, Any] = {"bdc_daily": [], "bdc_weekly": [], "analytics": []}
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file() or p.name.startswith("._"):
            continue
        low = str(p).lower()
        bn = p.name
        if low.endswith(".plsql"):
            found["plsql"] = _prefer_db_path(found.get("plsql"), p)
        elif low.endswith(".epsql"):
            found["epsql"] = _prefer_db_path(found.get("epsql"), p)
        elif low.endswith(".bgsql"):
            found["bgsql"] = _prefer_db_path(found.get("bgsql"), p)
        elif bn == "BatteryUISysdiagnose.plist":
            found["bui_sd"] = p
        elif bn == "BatteryUI.plist":
            found["bui"] = p
        elif bn == "BatteryHealth.log" and "batteryhealth" in low:
            found["bhealth"] = p
        elif bn == "com.apple.powerd.bdc.plist":
            found["bdc_plist"] = p
        elif "bdc_daily_" in low and low.endswith(".csv"):
            found["bdc_daily"].append(p)
        elif "bdc_weekly_" in low and low.endswith(".csv"):
            found["bdc_weekly"].append(p)
        elif bn.lower().startswith("analytics-") and (low.endswith(".ips") or low.endswith(".ips.synced")):
            found["analytics"].append(p)
    return found


def _get_tables(cur: sqlite3.Cursor) -> set[str]:
    return {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}


def _get_cols(cur: sqlite3.Cursor, table: str) -> list[str]:
    return [r[1] for r in cur.execute(f"PRAGMA table_info({_qident(table)})").fetchall()]


def _parse_battery_health_log(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    res: dict[str, Any] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = [x.strip().strip('";') for x in line.split("=", 1)]
        if "Maximum Capacity Percent" in k or k == "MaximumCapacityPercent":
            res["ios_health_percent"] = _safe_int(v)
        elif "Battery Service State" in k or k == "ServiceOption":
            res["service_state"] = _safe_int(v)
        elif "Battery Service Flags" in k or k == "batteryServiceFlags":
            res["service_flags"] = _safe_int(v)
    return res


def _parse_bui_sysdiagnose(path: Path) -> dict[str, Any]:
    try:
        data = plistlib.loads(path.read_bytes())
    except (plistlib.InvalidFileException, ExpatError, OSError) as exc:
        raise ValueError(f"Corrupt BatteryUISysdiagnose plist ({path.name}): {exc}") from exc
    if not isinstance(data, dict):
        return {}
    bd = data.get("Breakdown") or {}
    if not isinstance(bd, dict):
        return {}
    out: dict[str, Any] = {
        "suggestions": bd.get("PLBatteryUISuggestionArrayKey") or [],
        "day": {"total_energy_pct": None, "fg_min": 0.0, "bg_min": 0.0, "apps": []},
        "week": {"total_energy_pct": None, "fg_min": 0.0, "bg_min": 0.0, "apps": []},
    }
    for key, slot in [("PLBatteryUIQueryRangeDayKey", "day"), ("PLBatteryUIQueryRangeWeekKey", "week")]:
        rv = bd.get(key)
        if not isinstance(rv, dict):
            continue
        out[slot]["total_energy_pct"] = _safe_int(rv.get("PLBatteryUITotalEnergyKey"))
        fg = _safe_float(rv.get("PLBatteryUIForegroundTimeKey"), 0.0) or 0.0
        bg = _safe_float(rv.get("PLBatteryUIBackgroundTimeKey"), 0.0) or 0.0
        out[slot]["fg_min"] = round(fg / 60.0, 1)
        out[slot]["bg_min"] = round(bg / 60.0, 1)
        apps = []
        for a in rv.get("PLBatteryUIAppArrayKey") or []:
            if not isinstance(a, dict):
                continue
            pct = _safe_int(a.get("PLBatteryUIAppEnergyValueKey"), 0) or 0
            en = _safe_float(a.get("PLBatteryUIAppEnergyUsedKey"), 0.0) or 0.0
            afg = (_safe_float(a.get("PLBatteryUIAppForegroundRuntimeKey"), 0.0) or 0.0) / 60.0
            abg = (_safe_float(a.get("PLBatteryUIAppBackgroundRuntimeKey"), 0.0) or 0.0) / 60.0
            if pct > 0 or en > 1.0 or abg >= 5.0:
                apps.append(
                    {
                        "name": a.get("PLBatteryUIAppNameKey") or a.get("PLBatteryUIAppBundleIDKey") or "unknown",
                        "bundle_id": a.get("PLBatteryUIAppBundleIDKey") or "",
                        "energy_pct": pct,
                        "energy_used": round(en, 2),
                        "fg_min": round(afg, 1),
                        "bg_min": round(abg, 1),
                    }
                )
        apps.sort(key=lambda x: (x["energy_pct"], x["energy_used"]), reverse=True)
        out[slot]["apps"] = apps[:20]
    return out


def _parse_epsql(path: Path) -> dict[str, Any]:
    res: dict[str, Any] = {"degradation_history": [], "battery_auth": None, "yww": None, "design_capacity": None}
    conn = _ro_connect(path)
    try:
        cur = conn.cursor()
        tbls = _get_tables(cur)
        offset = 0.0
        if "PPTStorageOperator_TimeOffset_1095_1" in tbls:
            tcols = _get_cols(cur, "PPTStorageOperator_TimeOffset_1095_1")
            if "system" in tcols:
                order = 'ORDER BY "ID" DESC ' if "ID" in tcols else ""
                row = cur.execute(f'SELECT "system" FROM "PPTStorageOperator_TimeOffset_1095_1" {order}LIMIT 1').fetchone()
                if row and _safe_float(row[0]) is not None:
                    offset = float(row[0])

        if "BatteryDataCollection_BDC_Once_3650_1" in tbls:
            cols = _get_cols(cur, "BatteryDataCollection_BDC_Once_3650_1")
            order = 'ORDER BY "ID" DESC ' if "ID" in cols else ""
            row = cur.execute(f'SELECT * FROM "BatteryDataCollection_BDC_Once_3650_1" {order}LIMIT 1').fetchone()
            if row:
                d = dict(zip(cols, row))
                res["yww"] = d.get("YWW")
                res["design_capacity"] = _safe_int(d.get("DesignCapacity"))

        if "BatteryDataCollection_BDC_Weekly_1095_1" in tbls:
            wcols = _get_cols(cur, "BatteryDataCollection_BDC_Weekly_1095_1")
            if "BatteryAuth" in wcols:
                order = 'ORDER BY "ID" DESC ' if "ID" in wcols else ""
                row = cur.execute(
                    f'SELECT "BatteryAuth" FROM "BatteryDataCollection_BDC_Weekly_1095_1" WHERE "BatteryAuth" IS NOT NULL {order}LIMIT 1'
                ).fetchone()
                if row:
                    res["battery_auth"] = _safe_int(row[0])

        if "BatteryDataCollection_BDC_Daily_1095_1" in tbls:
            cols = _get_cols(cur, "BatteryDataCollection_BDC_Daily_1095_1")
            need = [c for c in ("timestamp", "CycleCount", "MaxCapacityPercent", "NominalChargeCapacity", "Qmax0", "WeightedRa") if c in cols]
            if need:
                qcols = ", ".join(_qident(c) for c in need)
                order = ' ORDER BY "ID" ASC' if "ID" in cols else ""
                rows = cur.execute(f'SELECT {qcols} FROM "BatteryDataCollection_BDC_Daily_1095_1"{order}').fetchall()
                if rows:
                    pick = sorted({0, len(rows) // 2, len(rows) - 1})
                    for idx in pick:
                        d = dict(zip(need, rows[idx]))
                        ts_val = _safe_float(d.get("timestamp"))
                        res["degradation_history"].append(
                            {
                                "date": fmt_ts((ts_val + offset) if ts_val is not None else None),
                                "cycle_count": _safe_int(d.get("CycleCount")),
                                "health_pct": _safe_int(d.get("MaxCapacityPercent")),
                                "ncc_mah": _safe_int(d.get("NominalChargeCapacity")),
                                "qmax_mah": _safe_int(d.get("Qmax0")),
                                "weighted_ra_mohm": _safe_int(d.get("WeightedRa")),
                            }
                        )
    finally:
        conn.close()
    return res


def _parse_bgsql(path: Path) -> dict[str, Any]:
    res: dict[str, Any] = {"thermal_pressure_events": 0, "max_thermal_pressure": 0, "peak_power_events": 0, "max_peak_power_pressure": 0}
    conn = _ro_connect(path)
    try:
        cur = conn.cursor()
        tbls = _get_tables(cur)
        pm_tbl = next((t for t in sorted(tbls) if t.startswith("BackgroundProcessing_SystemConditionsPowerManagement")), None)
        if pm_tbl:
            cols = set(_get_cols(cur, pm_tbl))
            if {"ThermalPressure", "PeakPowerPressure"}.issubset(cols):
                row = cur.execute(
                    f'SELECT SUM(CASE WHEN ThermalPressure > 0 THEN 1 ELSE 0 END), MAX(ThermalPressure), '
                    f'SUM(CASE WHEN PeakPowerPressure > 0 THEN 1 ELSE 0 END), MAX(PeakPowerPressure) FROM {_qident(pm_tbl)}'
                ).fetchone()
                if row:
                    res["thermal_pressure_events"] = _safe_int(row[0], 0) or 0
                    res["max_thermal_pressure"] = _safe_int(row[1], 0) or 0
                    res["peak_power_events"] = _safe_int(row[2], 0) or 0
                    res["max_peak_power_pressure"] = _safe_int(row[3], 0) or 0
    finally:
        conn.close()
    return res


def _parse_plsql(path: Path) -> dict[str, Any]:
    conn = _ro_connect(path)
    try:
        cur = conn.cursor()
        tbls = _get_tables(cur)
        offset = 0.0
        if "PLStorageOperator_EventForward_TimeOffset" in tbls:
            tcols = _get_cols(cur, "PLStorageOperator_EventForward_TimeOffset")
            if "system" in tcols:
                order = 'ORDER BY "ID" DESC ' if "ID" in tcols else ""
                row = cur.execute(f'SELECT "system" FROM "PLStorageOperator_EventForward_TimeOffset" {order}LIMIT 1').fetchone()
                if row and _safe_float(row[0]) is not None:
                    offset = float(row[0])

        device_cfg: dict[str, Any] = {}
        if "PLConfigAgent_EventNone_Config" in tbls:
            cols = _get_cols(cur, "PLConfigAgent_EventNone_Config")
            order = 'ORDER BY "ID" DESC ' if "ID" in cols else ""
            row = cur.execute(f'SELECT * FROM "PLConfigAgent_EventNone_Config" {order}LIMIT 1').fetchone()
            if row:
                d = dict(zip(cols, row))
                boot_ts = _safe_float(d.get("DeviceBootTime"))
                now_ts = _safe_float(d.get("timestamp"))
                uptime_days = None
                if boot_ts is not None and now_ts is not None and now_ts >= boot_ts:
                    uptime_days = round((now_ts - boot_ts) / 86400.0, 1)
                auto_lock = _safe_int(d.get("AutoLockTime"))
                device_cfg = {
                    "hardware_model": d.get("Device"),
                    "installed_splat": d.get("InstalledSplat"),
                    "build": d.get("Build"),
                    "storage_gb": _safe_int(d.get("DeviceDiskSize")),
                    "free_gb": _safe_int(d.get("RemainingDiskSpace")),
                    "auto_lock_sec": auto_lock,
                    "auto_lock_never": (auto_lock is not None and auto_lock >= 2_000_000_000),
                    "uptime_days": uptime_days,
                }

        batt_cfg: dict[str, Any] = {}
        for tbl in ("PLBatteryAgent_EventNone_BatteryConfig", "PLBatteryAgent_EventNone_BatteryConfigPack0"):
            if tbl in tbls:
                cols = _get_cols(cur, tbl)
                order = 'ORDER BY "ID" DESC ' if "ID" in cols else ""
                row = cur.execute(f"SELECT * FROM {_qident(tbl)} {order}LIMIT 1").fetchone()
                if row:
                    d = dict(zip(cols, row))
                    ra_vals = [v for k, v in d.items() if k.startswith("RaTable_") and _safe_int(v) is not None]
                    batt_cfg = {
                        "cycle_count": _safe_int(d.get("CycleCount")),
                        "nominal_charge_capacity_mah": _safe_int(d.get("NominalChargeCapacity")),
                        "apple_raw_max_mah": _safe_int(d.get("AppleRawMaxCapacity")),
                        "ios_health_percent": _safe_int(d.get("MaximumCapacityPercent")),
                        "service_option": _safe_int(d.get("ServiceOption")),
                        "service_flags": _safe_int(d.get("batteryServiceFlags")),
                        "battery_serial_changed": _safe_int(d.get("BatterySerialChanged")),
                        "weighted_ra_mohm": _safe_int(d.get("WeightedRa")),
                        "ra_table_max_mohm": max((_safe_int(x, 0) or 0) for x in ra_vals) if ra_vals else None,
                        "week_mfd": _safe_int(d.get("WeekMfd")),
                        "operating_hours": _safe_int(d.get("TotalOperatingTime")),
                        "lifetime_upo_count": _safe_int(d.get("LifetimeUPOCount")),
                        "voltage_min_hist_mv": _safe_int(d.get("MinimumPackVoltage")),
                        "max_discharge_ma": _safe_int(d.get("MaximumDischargeCurrent")),
                    }
                    break

        timeline: dict[str, Any] = {}
        max_batt_ts = None
        if "PLBatteryAgent_EventBackward_Battery" in tbls:
            bcols = set(_get_cols(cur, "PLBatteryAgent_EventBackward_Battery"))
            if {"timestamp", "Voltage", "Temperature", "InstantAmperage"}.issubset(bcols):
                raw_min_expr = "MIN(AppleRawMaxCapacity)" if "AppleRawMaxCapacity" in bcols else "NULL"
                raw_max_expr = "MAX(AppleRawMaxCapacity)" if "AppleRawMaxCapacity" in bcols else "NULL"
                cyc_min_expr = "MIN(CycleCount)" if "CycleCount" in bcols else "NULL"
                cyc_max_expr = "MAX(CycleCount)" if "CycleCount" in bcols else "NULL"
                agg = cur.execute(
                    f"SELECT MIN(timestamp), MAX(timestamp), COUNT(*), MIN(Voltage), MAX(Voltage), MAX(Temperature), "
                    f"{raw_min_expr}, {raw_max_expr}, {cyc_min_expr}, {cyc_max_expr}, "
                    f"SUM(CASE WHEN Temperature >= 39.0 THEN 1 ELSE 0 END) "
                    f"FROM PLBatteryAgent_EventBackward_Battery"
                ).fetchone()
                if "IsCharging" in bcols:
                    idle = cur.execute(
                        "SELECT COUNT(*), AVG(InstantAmperage) FROM PLBatteryAgent_EventBackward_Battery "
                        "WHERE IsCharging=0 AND InstantAmperage BETWEEN -20 AND -1"
                    ).fetchone()
                else:
                    idle = None
                if agg and _safe_float(agg[1]) is not None:
                    max_batt_ts = _safe_float(agg[1])
                    t0 = _safe_float(agg[0])
                    max_t_val = _safe_float(agg[5])
                    timeline = {
                        "span_hours": round((max_batt_ts - t0) / 3600.0, 2) if (max_batt_ts is not None and t0 is not None and max_batt_ts >= t0) else None,
                        "samples": _safe_int(agg[2]),
                        "voltage_min_mv": _safe_int(agg[3]),
                        "voltage_max_mv": _safe_int(agg[4]),
                        "max_temp_c": round(max_t_val, 2) if max_t_val is not None else None,
                        "raw_max_min_mah": _safe_int(agg[6]),
                        "raw_max_max_mah": _safe_int(agg[7]),
                        "cycle_count": _safe_int(agg[9]),
                        "high_temp_39c_samples": _safe_int(agg[10], 0) or 0,
                        "idle_standby_samples": _safe_int(idle[0], 0) if idle else 0,
                        "idle_standby_avg_ma": round(_safe_float(idle[1], 0.0) or 0.0, 1) if (idle and _safe_float(idle[1]) is not None) else None,
                    }

        # CPMS active power throttling (iOS 26/27 PPMStatsCPMSPowerReduction: Sys1s_10-19%..90-99%, Sys1s_100%, or 50+%)
        cpms_throttling: dict[str, Any] = {
            "detected": False,
            "reduction_ge10_sec": 0.0,
            "reduction_10_49_sec": 0.0,
            "reduction_50_plus_sec": 0.0,
            "max_reduction_pct": 0,
            "peak_power_transitions": 0,
        }
        if "PLIOReportAgent_EventBackward_PPMStatsCPMSPowerReduction" in tbls:
            rcols = _get_cols(cur, "PLIOReportAgent_EventBackward_PPMStatsCPMSPowerReduction")
            bin_re = re.compile(r"^Sys1s_(\d+)(?:-(\d+))?\+?%\+?$")
            target_cols: list[tuple[str, int, int]] = []
            for col in rcols:
                m_bin = bin_re.match(col)
                if m_bin:
                    lo = int(m_bin.group(1))
                    hi = int(m_bin.group(2)) if m_bin.group(2) else lo
                    if lo >= 10:
                        target_cols.append((col, lo, hi))
            if target_cols:
                select_expr = ", ".join(f"SUM(COALESCE({_qident(c)},0))" for c, _, _ in target_cols)
                row_vals = cur.execute(
                    f"SELECT {select_expr} FROM PLIOReportAgent_EventBackward_PPMStatsCPMSPowerReduction"
                ).fetchone() or ()
                sec_10_49 = 0.0
                sec_50_plus = 0.0
                max_bin = 0
                for (_, lo, hi), raw_val in zip(target_cols, row_vals):
                    s = _safe_float(raw_val, 0.0) or 0.0
                    if s > 0.0:
                        if lo >= 50:
                            sec_50_plus += s
                        else:
                            sec_10_49 += s
                        if s > 0.5:
                            max_bin = max(max_bin, hi)
                tot_red = sec_10_49 + sec_50_plus
                cpms_throttling["reduction_ge10_sec"] = round(tot_red, 1)
                cpms_throttling["reduction_10_49_sec"] = round(sec_10_49, 1)
                cpms_throttling["reduction_50_plus_sec"] = round(sec_50_plus, 1)
                cpms_throttling["max_reduction_pct"] = max_bin
                cpms_throttling["detected"] = tot_red > 0.5
        if "PLIOReportAgent_EventBackward_PPMStatsPeakPowerPressure" in tbls:
            pcols = _get_cols(cur, "PLIOReportAgent_EventBackward_PPMStatsPeakPowerPressure")
            tcols = [c for c in pcols if c in ("PPPNotif_1_Transitions", "PPPNotif_2_Transitions", "PPPNotif_3_Transitions")]
            if tcols:
                expr = " + ".join(f"COALESCE({_qident(c)},0)" for c in tcols)
                val = cur.execute(f"SELECT SUM({expr}) FROM PLIOReportAgent_EventBackward_PPMStatsPeakPowerPressure").fetchone()[0]
                cpms_throttling["peak_power_transitions"] = _safe_int(val, 0) or 0
                if cpms_throttling["peak_power_transitions"] > 0:
                    cpms_throttling["detected"] = True

        # UsageTime (daily screen-on / plugged-in averages)
        usage: dict[str, Any] = {}
        if "PLAppTimeService_Aggregate_UsageTime" in tbls:
            ucols = set(_get_cols(cur, "PLAppTimeService_Aggregate_UsageTime"))
            if {"timestamp", "PluggedIn", "ScreenOn"}.issubset(ucols):
                days_map: dict[str, list[float]] = {}
                for ts_v, plug, on_s in cur.execute("SELECT timestamp, PluggedIn, ScreenOn FROM PLAppTimeService_Aggregate_UsageTime"):
                    tfv = _safe_float(ts_v)
                    if tfv is None:
                        continue
                    try:
                        d_str = datetime.fromtimestamp(tfv + offset, tz=timezone.utc).strftime("%Y-%m-%d")
                    except (ValueError, OverflowError, OSError):
                        continue
                    bucket = days_map.setdefault(d_str, [0.0, 0.0])
                    bucket[0] += (_safe_float(on_s, 0.0) or 0.0) / 3600.0
                    bucket[1] += (_safe_float(plug, 0.0) or 0.0) / 3600.0
                if days_map:
                    n_days = len(days_map)
                    usage = {
                        "days_observed": n_days,
                        "avg_screen_on_hours_per_day": round(sum(v[0] for v in days_map.values()) / n_days, 2),
                        "avg_plugged_in_hours_per_day": round(sum(v[1] for v in days_map.values()) / n_days, 2),
                        "max_screen_on_hours_day": round(max(v[0] for v in days_map.values()), 2),
                    }

        # Top RootNodeEnergy (last 24h hourly preferred, else all)
        cut24 = (max_batt_ts - 86400.0) if max_batt_ts is not None else 0.0
        root_nodes: list[dict[str, Any]] = []
        if {"PLAccountingOperator_Aggregate_RootNodeEnergy", "PLAccountingOperator_EventNone_Nodes"}.issubset(tbls):
            ecols = set(_get_cols(cur, "PLAccountingOperator_Aggregate_RootNodeEnergy"))
            ncols = set(_get_cols(cur, "PLAccountingOperator_EventNone_Nodes"))
            if {"NodeID", "Energy"}.issubset(ecols) and {"ID", "Name"}.issubset(ncols):
                rows = []
                if {"timeInterval", "timestamp"}.issubset(ecols):
                    rows = cur.execute(
                        """
                        SELECT n.Name, ROUND(SUM(e.Energy), 1) AS en
                        FROM PLAccountingOperator_Aggregate_RootNodeEnergy e
                        LEFT JOIN PLAccountingOperator_EventNone_Nodes n ON e.NodeID = n.ID
                        WHERE e.timeInterval = 3600 AND e.timestamp >= ?
                        GROUP BY n.Name ORDER BY en DESC LIMIT 15
                        """,
                        (cut24,),
                    ).fetchall()
                if not rows:
                    rows = cur.execute(
                        """
                        SELECT n.Name, ROUND(SUM(e.Energy), 1) AS en
                        FROM PLAccountingOperator_Aggregate_RootNodeEnergy e
                        LEFT JOIN PLAccountingOperator_EventNone_Nodes n ON e.NodeID = n.ID
                        GROUP BY n.Name ORDER BY en DESC LIMIT 15
                        """
                    ).fetchall()
                tot_en = sum((_safe_float(r[1], 0.0) or 0.0) for r in rows)
                for name, en in rows:
                    ev = _safe_float(en, 0.0) or 0.0
                    root_nodes.append({"name": name or "unknown", "energy": ev, "share_pct": round(ev * 100.0 / tot_en, 1) if tot_en > 0 else 0.0})

        # Wakes, Push, Location, Signal Bars, Telephony
        wakes_24h = 0
        wake_reasons: list[dict[str, Any]] = []
        if "PLSleepWakeAgent_EventForward_PowerState" in tbls:
            ps_cols = set(_get_cols(cur, "PLSleepWakeAgent_EventForward_PowerState"))
            if {"State", "Event", "timestamp"}.issubset(ps_cols):
                wakes_24h = _safe_int(
                    cur.execute("SELECT COUNT(*) FROM PLSleepWakeAgent_EventForward_PowerState WHERE State=1 AND Event=3 AND timestamp >= ?", (cut24,)).fetchone()[0],
                    0,
                ) or 0
            if "PLSleepWakeAgent_EventForward_PowerState_Array_Reason" in tbls and {"ID", "timestamp"}.issubset(ps_cols):
                r_cols = set(_get_cols(cur, "PLSleepWakeAgent_EventForward_PowerState_Array_Reason"))
                if {"value", "FK_ID"}.issubset(r_cols):
                    for val, cnt in cur.execute(
                        """
                        SELECT ar.value, COUNT(*) FROM PLSleepWakeAgent_EventForward_PowerState_Array_Reason ar
                        JOIN PLSleepWakeAgent_EventForward_PowerState ps ON ar.FK_ID = ps.ID
                        WHERE ps.timestamp >= ?
                        GROUP BY ar.value ORDER BY COUNT(*) DESC LIMIT 12
                        """,
                        (cut24,),
                    ):
                        wake_reasons.append({"reason": val, "count": _safe_int(cnt, 0)})

        pushes: list[dict[str, Any]] = []
        if "PLPushAgent_EventPoint_ReceivedPush" in tbls:
            p_cols = set(_get_cols(cur, "PLPushAgent_EventPoint_ReceivedPush"))
            if {"BundleID", "ConnectionType", "DidWake", "timestamp"}.issubset(p_cols):
                for bid, conn_t, did_w, cnt in cur.execute(
                    """
                    SELECT BundleID, ConnectionType, DidWake, COUNT(*)
                    FROM PLPushAgent_EventPoint_ReceivedPush WHERE timestamp >= ?
                    GROUP BY BundleID, ConnectionType, DidWake ORDER BY COUNT(*) DESC LIMIT 15
                    """,
                    (cut24,),
                ):
                    pushes.append({"bundle_id": bid, "connection": conn_t, "did_wake": _safe_int(did_w, 0), "count": _safe_int(cnt, 0)})

        net_wakes: list[dict[str, Any]] = []
        if "PLNetworkAgent_EventPoint_Wake" in tbls:
            n_cols = set(_get_cols(cur, "PLNetworkAgent_EventPoint_Wake"))
            if {"ProcessName", "Interface"}.issubset(n_cols):
                for proc, iface, cnt in cur.execute(
                    "SELECT ProcessName, Interface, COUNT(*) FROM PLNetworkAgent_EventPoint_Wake GROUP BY ProcessName, Interface ORDER BY COUNT(*) DESC LIMIT 12"
                ):
                    net_wakes.append({"process": proc, "interface": iface, "count": _safe_int(cnt, 0)})

        loc_clients: list[dict[str, Any]] = []
        if "PLLocationAgent_EventForward_ClientStatus" in tbls:
            l_cols = set(_get_cols(cur, "PLLocationAgent_EventForward_ClientStatus"))
            if {"Client", "Type"}.issubset(l_cols):
                for cli, ltype, cnt in cur.execute(
                    "SELECT Client, Type, COUNT(*) FROM PLLocationAgent_EventForward_ClientStatus GROUP BY Client, Type ORDER BY COUNT(*) DESC LIMIT 12"
                ):
                    loc_clients.append({"client": cli, "type": ltype, "count": _safe_int(cnt, 0)})

        signal_bars: dict[str, float] = {}
        poor_signal_pct = 0.0
        if "PLAppTimeService_Aggregate_CellularCondition" in tbls:
            c_cols = set(_get_cols(cur, "PLAppTimeService_Aggregate_CellularCondition"))
            if {"SignalBars", "CellUsageTime"}.issubset(c_cols):
                rows = cur.execute(
                    "SELECT SignalBars, SUM(CellUsageTime) FROM PLAppTimeService_Aggregate_CellularCondition GROUP BY SignalBars ORDER BY SignalBars"
                ).fetchall()
                tot_cell = sum((_safe_float(r[1], 0.0) or 0.0) for r in rows)
                poor_sec = 0.0
                for b, sec in rows:
                    sv = _safe_float(sec, 0.0) or 0.0
                    if tot_cell > 0:
                        pct = round(sv * 100.0 / tot_cell, 1)
                        signal_bars[str(b)] = pct
                        if _safe_int(b, 4) in (0, 1, 2):
                            poor_sec += sv
                if tot_cell > 0:
                    poor_signal_pct = round(poor_sec * 100.0 / tot_cell, 1)

        rats: dict[str, int] = {}
        if "PLBBAgent_EventPoint_TelephonyActivity" in tbls:
            ta_cols = set(_get_cols(cur, "PLBBAgent_EventPoint_TelephonyActivity"))
            if "campedRat" in ta_cols:
                for rat, cnt in cur.execute("SELECT campedRat, COUNT(*) FROM PLBBAgent_EventPoint_TelephonyActivity GROUP BY campedRat ORDER BY COUNT(*) DESC"):
                    rats[str(rat or "None")] = _safe_int(cnt, 0) or 0

        reg_drops = 0
        if "PLBBAgent_EventForward_TelephonyRegistration" in tbls:
            tr_cols = set(_get_cols(cur, "PLBBAgent_EventForward_TelephonyRegistration"))
            if "status" in tr_cols:
                reg_drops = _safe_int(
                    cur.execute("SELECT COUNT(*) FROM PLBBAgent_EventForward_TelephonyRegistration WHERE status IN ('EmergencyOnly', 'NotRegistered')").fetchone()[0],
                    0,
                ) or 0

        # Background location / Hey Siri / Low Power Mode
        bg_location_apps: list[dict[str, Any]] = []
        if "PLAppTimeService_Aggregate_AppRunTime" in tbls:
            ar_cols = set(_get_cols(cur, "PLAppTimeService_Aggregate_AppRunTime"))
            if {"BundleID", "BackgroundLocationTime"}.issubset(ar_cols):
                for bid, mins in cur.execute(
                    "SELECT BundleID, ROUND(SUM(BackgroundLocationTime)/60.0, 1) AS m FROM PLAppTimeService_Aggregate_AppRunTime "
                    "GROUP BY BundleID HAVING m >= 1.0 ORDER BY m DESC LIMIT 10"
                ):
                    bg_location_apps.append({"bundle_id": bid, "bg_location_min": _safe_float(mins, 0.0)})

        hey_siri = None
        if "PLSiriAgent_EventForward_SiriConfig" in tbls:
            sc_cols = _get_cols(cur, "PLSiriAgent_EventForward_SiriConfig")
            if "HeySiriEnabled" in sc_cols:
                order = 'ORDER BY "ID" DESC ' if "ID" in sc_cols else ""
                r = cur.execute(f'SELECT "HeySiriEnabled" FROM "PLSiriAgent_EventForward_SiriConfig" {order}LIMIT 1').fetchone()
                hey_siri = bool(_safe_int(r[0], 0)) if r else None

        low_power_mode = None
        if "PLDuetService_EventForward_BatterySaverMode" in tbls:
            bs_cols = _get_cols(cur, "PLDuetService_EventForward_BatterySaverMode")
            if "Value" in bs_cols:
                order = 'ORDER BY "ID" DESC ' if "ID" in bs_cols else ""
                r = cur.execute(f'SELECT "Value" FROM "PLDuetService_EventForward_BatterySaverMode" {order}LIMIT 1').fetchone()
                low_power_mode = bool(_safe_int(r[0], 0)) if r else None

        return {
            "device_cfg": device_cfg,
            "battery_cfg": batt_cfg,
            "timeline": timeline,
            "cpms_throttling": cpms_throttling,
            "usage": usage,
            "root_nodes_24h": root_nodes,
            "wakes_24h": wakes_24h,
            "wake_reasons_24h": wake_reasons,
            "pushes_24h": pushes,
            "network_wakes": net_wakes,
            "location_clients": loc_clients,
            "bg_location_apps": bg_location_apps,
            "cellular": {
                "rats": rats,
                "signal_bars_pct": signal_bars,
                "poor_signal_pct": poor_signal_pct,
                "registration_drops": reg_drops,
            },
            "hey_siri_enabled": hey_siri,
            "low_power_mode_enabled": low_power_mode,
        }
    finally:
        conn.close()


def analyze_ios_artifacts(
    target: Path,
    work_dir: Path | None = None,
    quick_hardware: dict[str, Any] | None = None,
    device_meta: dict[str, Any] | None = None,
    analytics_files: list[Path] | None = None,
) -> dict[str, Any]:
    """Build unified diagnostic JSON payload from iOS sysdiagnose, extracted dir, PLSQL, or JSON fixture."""
    lname = target.name.lower()
    if target.is_file() and lname.endswith(".json"):
        raw = json.loads(target.read_text(encoding="utf-8"), parse_constant=_reject_bad_json_const)
        if not isinstance(raw, dict):
            raise ValueError(f"Expected JSON object in {target}")
        if "platform" in raw and "hardware_battery" in raw:
            return raw

    found: dict[str, Any] = {}
    if target.is_file() and (lname.endswith(".tar.gz") or lname.endswith(".tgz")):
        extract_to = work_dir or (target.parent / f"{target.stem.replace('.tar', '')}_extracted")
        found = safe_extract_sysdiagnose(target, extract_to)
    elif target.is_file() and lname.endswith(".plsql"):
        found = {"plsql": target, "bdc_daily": [], "bdc_weekly": [], "analytics": []}
    elif target.is_dir():
        found = discover_extracted_dir(target)

    bh = _parse_battery_health_log(found["bhealth"]) if "bhealth" in found else {}
    bui = _parse_bui_sysdiagnose(found["bui_sd"]) if "bui_sd" in found else {}
    ep = _parse_epsql(found["epsql"]) if "epsql" in found else {}
    bg = _parse_bgsql(found["bgsql"]) if "bgsql" in found else {}
    pl = _parse_plsql(found["plsql"]) if "plsql" in found else {}

    # Also scan any pulled or extracted Analytics-*.ips* for extra battery metrics
    analytics_battery: dict[str, Any] = {}
    merged_analytics = sorted({*(analytics_files or []), *(found.get("analytics") or [])}, key=lambda p: p.name)
    for af in merged_analytics:
        if not af.exists():
            continue
        with af.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "MaximumCapacityPercent" in line or "AppleRawMaxCapacity" in line:
                    try:
                        obj = json.loads(line, parse_constant=_reject_bad_json_const)
                        msg = obj.get("message") if isinstance(obj, dict) else None
                        if isinstance(msg, dict):
                            v_hp = _safe_int(msg.get("last_value_MaximumCapacityPercent"))
                            if v_hp is not None:
                                analytics_battery["ios_health_percent"] = v_hp
                            v_cyc = _safe_int(msg.get("last_value_CycleCount"))
                            if v_cyc is not None:
                                analytics_battery["cycle_count"] = v_cyc
                            v_ncc = _safe_int(msg.get("last_value_NominalChargeCapacity"))
                            if v_ncc is not None:
                                analytics_battery["ncc_mah"] = v_ncc
                            v_wra = _safe_int(_first_not_none(msg.get("last_value_ChemicalWeightedRa"), msg.get("last_value_WeightedRa")))
                            if v_wra is not None:
                                analytics_battery["weighted_ra_mohm"] = v_wra
                    except (json.JSONDecodeError, ValueError):
                        pass

    qh = quick_hardware or {}
    dm = device_meta or {}
    dcfg = pl.get("device_cfg") or {}
    bcfg = pl.get("battery_cfg") or {}
    tl = pl.get("timeline") or {}

    design_mah = _first_not_none(_safe_int(qh.get("DesignCapacity")), _safe_int(ep.get("design_capacity")))
    ncc_mah = _first_not_none(
        _safe_int(qh.get("NominalChargeCapacity")),
        _safe_int(bcfg.get("nominal_charge_capacity_mah")),
        _safe_int(analytics_battery.get("ncc_mah")),
    )
    cap_pct = round(ncc_mah * 100.0 / design_mah, 1) if (design_mah and ncc_mah is not None and design_mah > 0) else None

    cpms_info = dict(pl.get("cpms_throttling") or {"detected": False, "reduction_10_49_sec": 0.0, "max_reduction_pct": 0, "peak_power_transitions": 0})
    bg_peak = bg.get("peak_power_events", 0) or 0
    if not cpms_info.get("detected") and bg_peak > 20:
        cpms_info["detected"] = True
        cpms_info["peak_power_transitions"] = max(cpms_info.get("peak_power_transitions", 0) or 0, bg_peak)

    qh_temp = _safe_float(qh.get("Temperature"))
    max_temp_c = _first_not_none(_safe_float(tl.get("max_temp_c")), round(qh_temp / 100.0, 2) if qh_temp is not None else None)

    hw_battery = {
        "cycle_count": _first_not_none(_safe_int(qh.get("CycleCount")), _safe_int(bcfg.get("cycle_count")), _safe_int(tl.get("cycle_count")), _safe_int(analytics_battery.get("cycle_count"))),
        "design_capacity_mah": design_mah,
        "nominal_charge_capacity_mah": ncc_mah,
        "capacity_retention_pct": cap_pct,
        "raw_max_min_mah": _safe_int(tl.get("raw_max_min_mah")),
        "ios_health_percent": _first_not_none(_safe_int(bh.get("ios_health_percent")), _safe_int(bcfg.get("ios_health_percent")), _safe_int(analytics_battery.get("ios_health_percent"))),
        "service_state": _first_not_none(_safe_int(bh.get("service_state")), _safe_int(bcfg.get("service_option"))),
        "battery_auth": ep.get("battery_auth"),
        "serial_changed": _safe_int(bcfg.get("battery_serial_changed")),
        "week_mfd": _safe_int(bcfg.get("week_mfd")),
        "yww": ep.get("yww"),
        "operating_hours": _safe_int(bcfg.get("operating_hours")),
        "weighted_ra_mohm": _first_not_none(_safe_int(qh.get("WeightedRa")), _safe_int(bcfg.get("weighted_ra_mohm")), _safe_int(analytics_battery.get("weighted_ra_mohm"))),
        "ra_table_max_mohm": _safe_int(bcfg.get("ra_table_max_mohm")),
        "voltage_min_mv": _first_not_none(_safe_int(tl.get("voltage_min_mv")), _safe_int(bcfg.get("voltage_min_hist_mv"))),
        "max_temp_c": max_temp_c,
        "high_temp_39c_samples": _safe_int(tl.get("high_temp_39c_samples"), 0),
        "lifetime_upo_count": _safe_int(bcfg.get("lifetime_upo_count"), 0),
        "cpms_throttling": cpms_info,
        "bg_thermal_pressure_events": bg.get("thermal_pressure_events", 0),
        "bg_peak_power_events": bg.get("peak_power_events", 0),
        "idle_standby_avg_ma": tl.get("idle_standby_avg_ma"),
        "degradation_history": ep.get("degradation_history") or [],
    }

    device = {
        "device_name": dm.get("DeviceName"),
        "product_type": dm.get("ProductType") or dcfg.get("hardware_model"),
        "hardware_model": dm.get("HardwareModel") or dcfg.get("hardware_model"),
        "os_version": dm.get("ProductVersion") or dcfg.get("installed_splat"),
        "build_version": dm.get("BuildVersion") or dcfg.get("build"),
        "udid": dm.get("UniqueDeviceID"),
        "battery_serial": qh.get("Serial"),
        "storage_gb": _safe_int(dcfg.get("storage_gb")),
        "free_gb": _safe_int(dcfg.get("free_gb")),
        "auto_lock_never": bool(dcfg.get("auto_lock_never", False)),
        "uptime_days": dcfg.get("uptime_days"),
    }

    src_sha256 = file_sha256(target) if target.is_file() else None
    return {
        "platform": "ios",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **({"source_sha256": src_sha256} if src_sha256 else {}),
        "device": device,
        "hardware_battery": hw_battery,
        "usage": pl.get("usage") or {},
        "battery_ui": bui,
        "software_and_radio": {
            "root_nodes_24h": pl.get("root_nodes_24h") or [],
            "wakes_24h": pl.get("wakes_24h"),
            "span_hours": tl.get("span_hours"),
            "wake_reasons_24h": pl.get("wake_reasons_24h") or [],
            "pushes_24h": pl.get("pushes_24h") or [],
            "network_wakes": pl.get("network_wakes") or [],
            "location_clients": pl.get("location_clients") or [],
            "bg_location_apps": pl.get("bg_location_apps") or [],
            "cellular": pl.get("cellular") or {},
            "hey_siri_enabled": pl.get("hey_siri_enabled"),
            "low_power_mode_enabled": pl.get("low_power_mode_enabled"),
        },
    }
