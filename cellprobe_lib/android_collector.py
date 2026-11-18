#!/usr/bin/env python3
"""
CellProbe Android Collector & Batterystats Parser (Pure Python Stdlib via ADB).

Runs strictly read-only `adb shell` queries (`shell=False`, fixed arg lists)
and supports offline parsing of captured `dumpsys` bundles.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cellprobe_lib.ios_powerlog import _safe_float, _safe_int


class AndroidCollectorError(RuntimeError):
    """Clean, user-facing ADB error."""


def _find_adb() -> str:
    adb = shutil.which("adb")
    if adb:
        return adb
    cands = [
        Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe",
        Path(r"C:\platform-tools\adb.exe"),
        Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / "adb",
        Path.home() / "Android" / "Sdk" / "platform-tools" / "adb",
    ]
    for c in cands:
        if c.exists():
            return str(c)
    raise AndroidCollectorError("adb executable not found in PATH or standard platform-tools locations.")


def _run_adb(args: list[str], serial: str | None = None, timeout: int = 20) -> str:
    adb = _find_adb()
    cmd = [adb]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    try:
        proc = subprocess.run(cmd, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise AndroidCollectorError(f"ADB command timed out: {' '.join(args)}") from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip()
        raise AndroidCollectorError(f"ADB error: {err}")
    return proc.stdout


def list_android_devices() -> list[dict[str, str]]:
    out = _run_adb(["devices", "-l"], timeout=10)
    devices = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1], "detail": " ".join(parts[2:])})
    return devices


def parse_android_text_bundle(raw: str) -> dict[str, Any]:
    """Parse captured Android getprop + dumpsys battery + df + dumpsys batterystats text."""
    props: dict[str, str] = {}
    for m in re.finditer(r"\[([^\]]+)\]:\s*\[([^\]]*)\]", raw):
        props[m.group(1)] = m.group(2)

    # Storage from `df -k /data`
    storage_gb = None
    free_gb = None
    for line in raw.splitlines():
        if "/data" in line or "/storage" in line:
            nums = re.findall(r"\b(\d+)\s+(\d+)\s+(\d+)\s+\d+%", line)
            if nums:
                total_kb, _, avail_kb = (int(x) for x in nums[0])
                storage_gb = round(total_kb / (1024 * 1024), 1)
                free_gb = round(avail_kb / (1024 * 1024), 1)
                break

    # Battery section
    cycle_count = None
    ios_equiv_health = None
    temp_c = None
    voltage_mv = None
    design_mah = None
    est_cap_mah = None

    m_asoc = re.search(r"mSavedBatteryAsoc:\s*(\d+)", raw)
    if m_asoc:
        ios_equiv_health = _safe_int(m_asoc.group(1))
    m_usage = re.search(r"mSavedBatteryUsage:\s*(\d+)", raw)
    if m_usage:
        cycle_count = (_safe_int(m_usage.group(1), 0) or 0) // 100
    if cycle_count is None:
        m_cyc = re.search(r"(?:Cycle count(?:er)?|cycle_count|mBatteryCycleCount)\s*[:=]\s*(\d+)", raw, re.IGNORECASE)
        if m_cyc:
            cycle_count = _safe_int(m_cyc.group(1))

    m_temp = re.search(r"(?m)^\s*temperature:\s*(-?\d+)", raw)
    if m_temp:
        t_val = _safe_float(m_temp.group(1))
        if t_val is not None:
            temp_c = round(t_val / 10.0, 1)
    m_volt = re.search(r"(?m)^\s*voltage:\s*(\d+)", raw)
    if m_volt:
        v = _safe_int(m_volt.group(1))
        if v is not None:
            voltage_mv = v // 1000 if v > 20_000 else v
    m_cap = re.search(r"Estimated battery capacity:\s*([\d.]+)\s*mAh", raw)
    if m_cap:
        est_cap_mah = _safe_int(m_cap.group(1))
    m_des = re.search(r"charge_full_design\s*[:=]\s*(\d+)", raw)
    if m_des:
        v = _safe_int(m_des.group(1), 0) or 0
        design_mah = v // 1000 if v > 25_000 else v

    # Discharge & drain summary
    actual_drain_mah = None
    m_act = re.search(r"Actual drain:\s*([\d.]+)(?:-[\d.]+)?", raw, re.IGNORECASE)
    if m_act:
        actual_drain_mah = _safe_float(m_act.group(1))

    def _parse_dur_hours(label: str) -> float | None:
        m = re.search(rf"(?m)^\s*{re.escape(label)}:\s*([^\n(]+)", raw)
        if not m:
            return None
        s = m.group(1)
        hrs = 0.0
        for val, unit in re.findall(r"(\d+(?:\.\d+)?)\s*(ms|d|h|m|s)(?![A-Za-z])", s):
            fv = _safe_float(val, 0.0) or 0.0
            if unit == "d":
                hrs += fv * 24.0
            elif unit == "h":
                hrs += fv
            elif unit == "m":
                hrs += fv / 60.0
            elif unit == "s":
                hrs += fv / 3600.0
            elif unit == "ms":
                hrs += fv / 3_600_000.0
        return round(hrs, 2)

    screen_on_h = _parse_dur_hours("Screen on")
    time_on_batt_h = _parse_dur_hours("Time on battery")

    # Top UID / App power consumers
    top_apps: list[dict[str, Any]] = []
    for m in re.finditer(r"Uid\s+([a-zA-Z0-9_.*:-]+):\s+([\d.]+)\s+\(", raw):
        name, mah = m.group(1), _safe_float(m.group(2), 0.0) or 0.0
        if mah >= 1.0:
            top_apps.append({"name": name, "bundle_id": name, "energy_pct": 0, "energy_used": round(mah, 1), "fg_min": 0.0, "bg_min": 0.0})
    top_apps.sort(key=lambda x: x["energy_used"], reverse=True)
    tot_mah = sum(a["energy_used"] for a in top_apps) or 1.0
    for a in top_apps:
        a["energy_pct"] = int(round(a["energy_used"] * 100.0 / tot_mah))

    # Top wakelocks
    wakelocks: list[dict[str, Any]] = []
    for m in re.finditer(r"Wake lock\s+([^\n:]+):\s+([^\n]+?)\s+(?:partial|full)\s+\((\d+)\s+times\)", raw):
        wakelocks.append({"reason": m.group(1).strip(), "count": _safe_int(m.group(3), 0)})
    wakelocks.sort(key=lambda x: x["count"] or 0, reverse=True)

    # Cellular signal poor pct (none + poor vs total)
    poor_pct = 0.0
    sig_block = re.search(r"Cellular signal levels:([^\n]+(?:\n\s+[^\n]+)*)", raw)
    if sig_block:
        poor_sum = 0.0
        for lvl in ("none", "poor"):
            for pm in re.finditer(rf"\b{lvl}\b[^()]*\(([\d.]+)%\)", sig_block.group(1)):
                poor_sum += _safe_float(pm.group(1), 0.0) or 0.0
        poor_pct = round(poor_sum, 1)

    return {
        "platform": "android",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device": {
            "device_name": props.get("ro.product.model") or "Android Device",
            "product_type": props.get("ro.product.model") or "Android",
            "hardware_model": props.get("ro.product.manufacturer"),
            "os_version": f"Android {props.get('ro.build.version.release', '?')}",
            "build_version": props.get("ro.build.display.id"),
            "storage_gb": storage_gb,
            "free_gb": free_gb,
            "auto_lock_never": False,
            "uptime_days": None,
        },
        "hardware_battery": {
            "cycle_count": cycle_count,
            "design_capacity_mah": design_mah,
            "nominal_charge_capacity_mah": est_cap_mah,
            "capacity_retention_pct": round(est_cap_mah * 100.0 / design_mah, 1) if (est_cap_mah and design_mah and design_mah > 0) else None,
            "ios_health_percent": ios_equiv_health,
            "service_state": 1 if (ios_equiv_health is not None and ios_equiv_health < 80) else 0,
            "battery_auth": None,
            "weighted_ra_mohm": None,
            "voltage_min_mv": voltage_mv,
            "max_temp_c": temp_c,
            "lifetime_upo_count": 0,
            "cpms_throttling": {"detected": False, "reduction_10_49_sec": 0.0, "max_reduction_pct": 0},
            "bg_thermal_pressure_events": 0,
            "bg_peak_power_events": 0,
            "degradation_history": [],
            "actual_drain_mah": actual_drain_mah,
        },
        "usage": {
            "avg_screen_on_hours_per_day": screen_on_h,
            "time_on_battery_hours": time_on_batt_h,
        },
        "battery_ui": {"day": {"total_energy_pct": 100, "apps": top_apps[:15]}, "week": {"apps": []}},
        "software_and_radio": {
            "wake_reasons_24h": wakelocks[:12],
            "cellular": {"poor_signal_pct": poor_pct, "registration_drops": 0, "rats": {}},
            "bg_location_apps": [],
            "location_clients": [],
            "pushes_24h": [],
            "network_wakes": [],
            "root_nodes_24h": [],
        },
    }


def collect_android_live(serial: str | None = None, out_dir: Path | None = None) -> dict[str, Any]:
    devs = list_android_devices()
    ready = [d for d in devs if d["state"] == "device"]
    if not ready:
        unauth = [d for d in devs if d["state"] == "unauthorized"]
        if unauth:
            raise AndroidCollectorError("Android device detected as 'unauthorized'. Check the phone screen and allow USB Debugging.")
        raise AndroidCollectorError("No ADB-ready Android device detected. Enable Developer Options -> USB Debugging.")

    if serial:
        if not any(d["serial"] == serial for d in ready):
            raise AndroidCollectorError(f"Requested Android serial '{serial}' not found among authorized ADB devices.")
        target = serial
    else:
        if len(ready) > 1:
            raise AndroidCollectorError("Multiple Android devices connected via ADB. Pass --serial <serial>.")
        target = ready[0]["serial"]
    sections = []
    for label, cmd in [
        ("GETPROP", ["shell", "getprop"]),
        ("DF", ["shell", "df", "-k", "/data"]),
        ("BATTERY", ["shell", "dumpsys", "battery"]),
        ("BATTERYSTATS", ["shell", "dumpsys", "batterystats", "--charged"]),
    ]:
        out = _run_adb(cmd, serial=target, timeout=25)
        sections.append(f"=== {label} ===\n{out}")

    try:
        des_out = _run_adb(["shell", "cat", "/sys/class/power_supply/battery/charge_full_design"], serial=target, timeout=5).strip()
        if des_out.isdigit():
            sections.append(f"=== SYSFS_DESIGN ===\ncharge_full_design={des_out}\n")
    except AndroidCollectorError:
        pass

    bundle = "\n".join(sections)
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "android_dumpsys_bundle.txt").write_text(bundle, encoding="utf-8")

    return parse_android_text_bundle(bundle)
