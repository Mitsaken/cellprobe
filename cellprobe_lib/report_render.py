#!/usr/bin/env python3
"""
CellProbe Diagnostic Verdict Engine & Report Renderer (Pure Python Stdlib).

Evaluates hardware battery integrity, active CPMS throttling, storage pressure,
background wakeups, and cellular signal quality using a strict max-severity gate
(CRITICAL/HIGH never masked by cumulative scores). Outputs CLI text, compact AI
Markdown bundles, JSON, and zero-dependency self-contained HTML dashboards.
"""

from __future__ import annotations

import copy
import html
import json
import math
import re
from dataclasses import dataclass
from typing import Any

_USER_PATH_RE = re.compile(r"(?:[A-Za-z]:\\Users\\|/Users/|/home/)[^\s'\"\\/;:,]+")

SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0, "HEALTHY": 0}


@dataclass(frozen=True)
class Thresholds:
    health_warn: int = 80
    health_crit: int = 75
    cycles_high: int = 1000
    resistance_warn: int = 350
    resistance_crit: int = 500
    min_free_gb: int = 5
    poor_signal_warn: float = 35.0
    max_wakes_per_hr: float = 8.0

    def __post_init__(self) -> None:
        for name, val in (
            ("health_warn", self.health_warn),
            ("health_crit", self.health_crit),
            ("cycles_high", self.cycles_high),
            ("resistance_warn", self.resistance_warn),
            ("resistance_crit", self.resistance_crit),
            ("min_free_gb", self.min_free_gb),
            ("poor_signal_warn", self.poor_signal_warn),
            ("max_wakes_per_hr", self.max_wakes_per_hr),
        ):
            if isinstance(val, bool):
                raise ValueError(f"Threshold '{name}' must be numeric, not bool.")
            if not math.isfinite(float(val)) or float(val) <= 0:
                raise ValueError(f"Threshold '{name}' must be a positive finite number.")
        if self.resistance_warn > self.resistance_crit:
            raise ValueError("resistance_warn must be <= resistance_crit.")
        if self.health_crit > self.health_warn or self.health_warn > 100 or self.poor_signal_warn > 100.0:
            raise ValueError("Percentage thresholds must satisfy 0 < health_crit <= health_warn <= 100 and poor_signal_warn <= 100.")


_ID_KEYS = (
    "udid",
    "battery_serial",
    "serial_number",
    "serial",
    "imei",
    "meid",
    "iccid",
    "ecid",
    "wifi_mac",
    "bluetooth_mac",
    "android_serial",
)


def redact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Recursively scrub device identifiers, names, and OS user home paths across all report fields."""
    clean = copy.deepcopy(report)
    dev = clean.get("device") if isinstance(clean.get("device"), dict) else {}
    ids = {str(dev[k]) for k in _ID_KEYS if dev.get(k) and len(str(dev[k])) >= 6}
    dev_name = str(dev["device_name"]) if dev.get("device_name") else None
    if isinstance(dev, dict):
        for k in (*_ID_KEYS, "device_name"):
            if dev.get(k):
                dev[k] = "[REDACTED]"
    id_re = re.compile("|".join(re.escape(s) for s in sorted(ids, key=len, reverse=True)), re.IGNORECASE) if ids else None

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            out = "[REDACTED]" if (dev_name and node == dev_name) else node
            if id_re and out != "[REDACTED]":
                out = id_re.sub("[REDACTED]", out)
            return _USER_PATH_RE.sub("<USER_HOME>", out)
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        return node

    return _walk(clean)


def evaluate_findings(report: dict[str, Any], thresholds: Thresholds | None = None) -> dict[str, Any]:
    """Evaluate hardware, thermal/throttling, storage, and software/radio drain findings."""
    th = thresholds or Thresholds()
    hw = report.get("hardware_battery") or {}
    dev = report.get("device") or {}
    sw = report.get("software_and_radio") or {}
    bui = report.get("battery_ui") or {}
    usage = report.get("usage") or {}

    findings: list[dict[str, str]] = []

    def add(sev: str, cat: str, title: str, detail: str, action: str) -> None:
        findings.append({"severity": sev, "category": cat, "title": title, "detail": detail, "action": action})

    # 1. Hardware Battery Checks
    cycles = hw.get("cycle_count")
    health_pct = hw.get("ios_health_percent")
    cap_pct = hw.get("capacity_retention_pct")
    wra = hw.get("weighted_ra_mohm")
    upo = hw.get("lifetime_upo_count") or 0
    auth = hw.get("battery_auth")
    cpms = hw.get("cpms_throttling") or {}

    if upo > 0:
        add(
            "CRITICAL",
            "Hardware",
            "Unexpected Power-Off (UPO) Crashes Detected",
            f"LifetimeUPOCount = {upo}. Battery voltage sag triggered abrupt shutdowns.",
            "Replace the battery immediately to restore peak voltage stability.",
        )

    if auth == 0:
        add(
            "CRITICAL",
            "Hardware",
            "Unverified / Non-Genuine Battery Controller",
            "EPSQL BatteryAuth = 0 (controller failed Apple genuine authentication).",
            "Verify battery provenance before purchase or service.",
        )

    if cpms.get("detected"):
        red_sec = cpms.get("reduction_ge10_sec") if cpms.get("reduction_ge10_sec") is not None else cpms.get("reduction_10_49_sec", 0)
        add(
            "CRITICAL",
            "Hardware",
            "Active CPMS Power / CPU Throttling Engaged",
            f"System reduced peak power up to {cpms.get('max_reduction_pct', 0)}% "
            f"({red_sec}s under >=10% reduction; "
            f"{cpms.get('peak_power_transitions', 0)} peak-power pressure transitions).",
            "Plan battery service; high impedance or voltage/thermal limits forced CPMS power capping.",
        )

    if wra is not None:
        if wra >= th.resistance_crit:
            add(
                "CRITICAL",
                "Hardware",
                "Severe Internal Resistance (Cell Impedance)",
                f"WeightedRa = {wra} mOhm (>= {th.resistance_crit} mOhm critical threshold). Causes sharp voltage sag under load.",
                "Plan battery replacement; high impedance drives heat and premature % drops.",
            )
        elif wra >= th.resistance_warn:
            add(
                "HIGH",
                "Hardware",
                "Elevated Internal Resistance",
                f"WeightedRa = {wra} mOhm (>= {th.resistance_warn} mOhm). Aged cell chemistry.",
                "Battery service recommended if used as a daily primary device.",
            )

    eff_health = health_pct if health_pct is not None else (int(round(cap_pct)) if cap_pct is not None else None)
    service_flag = (hw.get("service_state") or 0) >= 1
    severely_degraded = bool(eff_health is not None and eff_health <= th.health_crit and (cycles or 0) >= th.cycles_high)
    if severely_degraded:
        add(
            "CRITICAL",
            "Hardware",
            "Severe Battery Degradation Indicators Detected",
            f"Battery Health = {eff_health}% (<= {th.health_crit}%), CycleCount = {cycles}, Retention = {cap_pct}% ({hw.get('nominal_charge_capacity_mah')}/{hw.get('design_capacity_mah')} mAh).",
            "Battery service or cell replacement recommended to restore full runtime stability.",
        )
    elif (eff_health is not None and eff_health < th.health_warn) or service_flag:
        svc_title = (
            f"Battery Service Recommended (<{th.health_warn}% Health)"
            if (eff_health is not None and eff_health < th.health_warn)
            else "Battery Service Flagged by OS"
        )
        add(
            "HIGH",
            "Hardware",
            svc_title,
            f"Battery Health = {eff_health if eff_health is not None else 'N/A'}%, CycleCount = {cycles}, Capacity = {hw.get('nominal_charge_capacity_mah')}/{hw.get('design_capacity_mah')} mAh.",
            "Consider replacement or use Low Power Mode / standby tuning for light backup duty.",
        )
    if cycles is not None and cycles >= th.cycles_high and not severely_degraded:
        add(
            "HIGH",
            "Hardware",
            "High Battery Cycle Count",
            f"CycleCount = {cycles} (>= {th.cycles_high} cycles).",
            "Inspect real mAh capacity vs design capacity (Apple rates iPhone <=14 for 500 cycles and iPhone 15+ for 1000 cycles; use --cycles-high 500 for older models).",
        )

    max_temp = hw.get("max_temp_c")
    therm_events = hw.get("bg_thermal_pressure_events") or 0
    if (max_temp is not None and max_temp >= 40.0) or therm_events >= 50:
        add(
            "HIGH",
            "Thermal",
            "Frequent Elevated Thermal Pressure",
            f"Peak observed temp = {max_temp} C, high-temp samples (>=39 C) = {hw.get('high_temp_39c_samples', 0)}, thermal pressure events = {therm_events}.",
            "Avoid fast charging while running heavy video/social apps; degraded cells generate extra I^2*R heat.",
        )

    # 2. Storage & System Config Checks
    free_gb = dev.get("free_gb")
    storage_gb = dev.get("storage_gb")
    if free_gb is not None:
        if free_gb <= 1:
            add(
                "CRITICAL",
                "Storage",
                "Critical Storage Exhaustion (NAND / Jetsam Thrashing)",
                f"Only {free_gb} GB free out of {storage_gb or '?'} GB. Triggers Jetsam kills, cache_delete loops, and high CPU overhead.",
                "Free at least 8-10 GB immediately (Instagram Delete+Reinstall, WhatsApp Manage Storage, Photos Recently Deleted) and reboot.",
            )
        elif free_gb < th.min_free_gb:
            add(
                "HIGH",
                "Storage",
                "Low Free Storage Space",
                f"Only {free_gb} GB free (< {th.min_free_gb} GB). May trigger background cache cleanup churn.",
                "Clear >= 5-10 GB of cached media/downloads.",
            )

    if dev.get("auto_lock_never"):
        add(
            "MEDIUM",
            "System",
            "Auto-Lock Set to 'Never'",
            "Display Auto-Lock is disabled (Never), risking unattended screen-on drain.",
            "Set Settings -> Display & Brightness -> Auto-Lock to 1 Minute (or 30 Seconds).",
        )

    # 3. Software, Background, Location & Wake Checks
    span_h = sw.get("span_hours")
    wakes_24h = sw.get("wakes_24h")
    if wakes_24h is not None and span_h is not None and isinstance(span_h, (int, float)) and not isinstance(span_h, bool) and math.isfinite(float(span_h)) and float(span_h) >= 1.0:
        denom = min(24.0, float(span_h))
        wakes_hr = wakes_24h / denom
        if wakes_hr >= th.max_wakes_per_hr:
            add(
                "MEDIUM",
                "Wakeups",
                "High Standby / Periodic Wakeup Rate",
                f"{wakes_24h} wakes in ~{denom:.1f}h ({wakes_hr:.1f} wakes/hr >= {th.max_wakes_per_hr}/hr threshold).",
                "Trim wake-push apps, lock-screen dynamic wallpapers, and Background App Refresh.",
            )

    # Dynamic wallpaper / Astronomy
    loc_clients = sw.get("location_clients") or []
    astro = [c for c in loc_clients if "AegirProxyApp" in (c.get("client") or "") or "MercuryPoster" in (c.get("client") or "")]
    if astro and sum(c.get("count") or 0 for c in astro) >= 15:
        cnt = sum(c.get("count") or 0 for c in astro)
        add(
            "MEDIUM",
            "Software",
            "Dynamic Astronomy / Weather Lock-Screen Polling Location",
            f"Lock screen poster queried Location {cnt} times in Powerlog.",
            "Switch Lock Screen wallpaper to a static Photo/Color instead of Astronomy/Weather.",
        )

    # Continuous background location apps
    bg_loc = [a for a in (sw.get("bg_location_apps") or []) if (a.get("bg_location_min") or 0) >= 15.0]
    if bg_loc:
        names = ", ".join(f"{a['bundle_id']} ({a['bg_location_min']}m)" for a in bg_loc[:3])
        add(
            "MEDIUM",
            "Location",
            "Apps Polling Location Continuously in Background",
            f"BackgroundLocationTime detected: {names}.",
            "Set Location access from 'Always' to 'While Using the App' for non-tracking apps.",
        )

    # Push notification wakes
    wake_pushes = [p for p in (sw.get("pushes_24h") or []) if (p.get("did_wake") or 0) == 1 and (p.get("count") or 0) >= 10]
    if wake_pushes:
        summary = ", ".join(f"{p['bundle_id']} ({p['count']}x/{p['connection']})" for p in wake_pushes[:3])
        add(
            "MEDIUM",
            "Notifications",
            "Frequent High-Priority Push Wakeups",
            f"24h wake-triggering pushes: {summary}.",
            "Enable Scheduled Summary or mute non-urgent channels for heavy push apps.",
        )

    # Active local VPN / ipsec security filtering overhead
    vpn_wakes = [n for n in (sw.get("network_wakes") or []) if str(n.get("interface", "")).startswith(("ipsec", "utun"))]
    week_apps = (bui.get("week") or {}).get("apps") or []
    vpn_apps = [a for a in week_apps if "bitdefender" in (a.get("bundle_id") or "").lower() and (a.get("energy_pct") or 0) >= 3]
    if vpn_wakes or vpn_apps:
        add(
            "MEDIUM",
            "Network",
            "Local VPN / Security Filter Tunnel Overhead",
            "Detected ipsec/utun tunnel or security web-filter app consuming background energy.",
            "Disable unused local VPN / Web Protection profiles in Settings -> General -> VPN & Device Management.",
        )

    # Hey Siri voice trigger wakes
    voice_trigs = sum((w.get("count") or 0) for w in (sw.get("wake_reasons_24h") or []) if "voice_trigger" in (w.get("reason") or ""))
    if sw.get("hey_siri_enabled") and voice_trigs >= 20:
        add(
            "MEDIUM",
            "Audio/Wake",
            "Always-On Voice Trigger Waking Device",
            f"'Hey Siri' DSP trigger caused {voice_trigs} device wakes in the last 24h.",
            "Turn off Listen for 'Hey Siri' if you use the Side Button instead.",
        )

    # Cellular poor signal & registration drops
    cell = sw.get("cellular") or {}
    poor_pct = cell.get("poor_signal_pct") or 0.0
    reg_drops = cell.get("registration_drops") or 0
    if poor_pct >= th.poor_signal_warn or reg_drops >= 5:
        add(
            "MEDIUM",
            "Cellular",
            "Weak Cellular Signal / Tower Re-Registration Drain",
            f"{poor_pct}% of cellular time spent at <=2 signal bars; {reg_drops} EmergencyOnly/NotRegistered drops.",
            "Prefer Wi-Fi Calling indoors; lock Voice & Data to LTE (avoid 5G On) in low-coverage areas.",
        )

    # Max severity strictly governs overall verdict (no cumulative score masking)
    max_rank = 0
    verdict = "HEALTHY"
    for f in findings:
        r = SEVERITY_ORDER.get(f["severity"], 0)
        if r > max_rank:
            max_rank = r
            verdict = f["severity"]

    hw_cats = {"Hardware", "Thermal"}
    hw_verdict = "HEALTHY"
    sw_verdict = "HEALTHY"
    for f in findings:
        target = "hw" if f["category"] in hw_cats else "sw"
        r = SEVERITY_ORDER.get(f["severity"], 0)
        cur = hw_verdict if target == "hw" else sw_verdict
        if r > SEVERITY_ORDER.get(cur, 0):
            if target == "hw":
                hw_verdict = f["severity"]
            else:
                sw_verdict = f["severity"]

    out = copy.deepcopy(report)
    out["verdict"] = verdict
    out["hardware_verdict"] = hw_verdict
    out["software_storage_verdict"] = sw_verdict
    out["findings"] = findings
    return out


def render_json(evaluated: dict[str, Any]) -> str:
    return json.dumps(evaluated, indent=2, ensure_ascii=False, allow_nan=False)


def _na(val: Any, suffix: str = "") -> str:
    return f"{val}{suffix}" if val is not None else "N/A"


def _num(val: Any, default: float = 0.0) -> float:
    if val is None or isinstance(val, bool):
        return default
    try:
        f = float(val)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def render_text(evaluated: dict[str, Any]) -> str:
    dev = evaluated.get("device") or {}
    hw = evaluated.get("hardware_battery") or {}
    usage = evaluated.get("usage") or {}
    sw = evaluated.get("software_and_radio") or {}
    bui = evaluated.get("battery_ui") or {}
    os_ver = str(dev.get("os_version") or "?")
    build_ver = str(dev.get("build_version") or "")
    os_disp = os_ver if (not build_ver or build_ver in os_ver) else f"{os_ver} (Build {build_ver})"
    top_period = "7-Day Sum" if ((bui.get("week") or {}).get("apps")) else "24h"
    cpms_blk = hw.get("cpms_throttling") or {}
    lines = [
        "=" * 78,
        f"CELLPROBE DIAGNOSTIC REPORT  |  Verdict: [{evaluated.get('verdict')}]",
        f"Hardware: {evaluated.get('hardware_verdict')}  |  Software/Storage/Radio: {evaluated.get('software_storage_verdict')}",
        "=" * 78,
        f"Device      : {dev.get('product_type') or 'N/A'} ({dev.get('hardware_model') or 'N/A'}) | {os_disp}",
        f"Storage     : Free {_na(dev.get('free_gb'), ' GB')} / {_na(dev.get('storage_gb'), ' GB')}  |  Auto-Lock Never: {dev.get('auto_lock_never')}  |  Uptime: {_na(dev.get('uptime_days'), 'd')}",
        f"Battery HW  : Cycles={_na(hw.get('cycle_count'))} | OS Health={_na(hw.get('ios_health_percent'), '%')} | Cap={_na(hw.get('nominal_charge_capacity_mah'))}/{_na(hw.get('design_capacity_mah'))} mAh ({_na(hw.get('capacity_retention_pct'), '%')})",
        f"Impedance   : WeightedRa={_na(hw.get('weighted_ra_mohm'), ' mOhm')} (RaTable max={_na(hw.get('ra_table_max_mohm'))}) | MinVolt={_na(hw.get('voltage_min_mv'), ' mV')} | MaxTemp={_na(hw.get('max_temp_c'), ' C')}",
        f"CPMS / Auth : Throttling={cpms_blk.get('detected')} (max -{cpms_blk.get('max_reduction_pct', 0)}%) | GenuineAuth={_na(hw.get('battery_auth'))} | UPO={_na(hw.get('lifetime_upo_count'))}",
        f"Usage / Idle: Avg ScreenOn={_na(usage.get('avg_screen_on_hours_per_day'), 'h/d')} | IdleCurrent={_na(hw.get('idle_standby_avg_ma'), ' mA')} | 24h Wakes={_na(sw.get('wakes_24h'))}",
        "",
        f"FINDINGS ({len(evaluated.get('findings') or [])}):",
    ]
    for i, f in enumerate(evaluated.get("findings") or [], 1):
        lines.append(f"  {i}. [{f.get('severity')}] ({f.get('category')}) {f.get('title')}")
        lines.append(f"     Why   : {f.get('detail')}")
        lines.append(f"     Action: {f.get('action')}")

    top_apps = (bui.get("week") or {}).get("apps") or (bui.get("day") or {}).get("apps") or []
    if top_apps:
        lines.append(f"\nTOP ENERGY CONSUMERS ({top_period}):")
        for a in top_apps[:8]:
            if isinstance(a, dict):
                lines.append(
                    f"  - {a.get('name', 'unknown')} ({a.get('bundle_id', '')}): "
                    f"{a.get('energy_pct', 0)}% | fg={a.get('fg_min', 0)}m | bg={a.get('bg_min', 0)}m"
                )

    lines.append("=" * 78)
    return "\n".join(lines)


def render_ai_bundle(evaluated: dict[str, Any]) -> str:
    """Compact, token-efficient Markdown diagnostic snapshot (<12 KB) for LLMs."""
    trimmed = redact_report(evaluated)
    bui = trimmed.get("battery_ui") or {}
    if isinstance(bui, dict):
        if isinstance(bui.get("suggestions"), list):
            bui["suggestions"] = bui["suggestions"][:3]
        for k in ("day", "week"):
            if isinstance(bui.get(k), dict) and isinstance(bui[k].get("apps"), list):
                bui[k]["apps"] = bui[k]["apps"][:8]
    sw = trimmed.get("software_and_radio") or {}
    if isinstance(sw, dict):
        for k in ("root_nodes_24h", "wake_reasons_24h", "pushes_24h", "network_wakes", "location_clients", "bg_location_apps"):
            if isinstance(sw.get(k), list):
                sw[k] = sw[k][:6]

    header = (
        "# CellProbe AI Forensic Brief\n\n"
        "> Paste this compact diagnostic bundle into Claude, ChatGPT, or Gemini to get tailored remediation advice.\n\n"
        f"**Verdict:** `{trimmed['verdict']}` (Hardware: `{trimmed['hardware_verdict']}`, Software/System: `{trimmed['software_storage_verdict']}`)\n\n"
    )
    payload = json.dumps(trimmed, indent=2, ensure_ascii=False, allow_nan=False)
    out = f"{header}```json\n{payload}\n```\n"
    if len(out.encode("utf-8")) >= 12288:
        if isinstance(bui, dict):
            bui.pop("suggestions", None)
            for k in ("day", "week"):
                if isinstance(bui.get(k), dict) and isinstance(bui[k].get("apps"), list):
                    bui[k]["apps"] = bui[k]["apps"][:5]
        if isinstance(sw, dict):
            for k in ("root_nodes_24h", "wake_reasons_24h", "pushes_24h", "network_wakes", "location_clients", "bg_location_apps"):
                if isinstance(sw.get(k), list):
                    sw[k] = sw[k][:4]
        payload = json.dumps(trimmed, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        out = f"{header}```json\n{payload}\n```\n"
    return out


def render_html(evaluated: dict[str, Any]) -> str:
    """Self-contained zero-CDN responsive HTML diagnostic dashboard."""
    dev = evaluated.get("device") or {}
    hw = evaluated.get("hardware_battery") or {}
    sw = evaluated.get("software_and_radio") or {}
    bui = evaluated.get("battery_ui") or {}
    verdict = str(evaluated.get("verdict", "HEALTHY"))
    badge_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "HEALTHY": "#22c55e"}.get(verdict, "#64748b")

    findings_html = ""
    for f in evaluated.get("findings") or []:
        if not isinstance(f, dict):
            continue
        fc = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308"}.get(str(f.get("severity")), "#38bdf8")
        findings_html += (
            f'<div class="card" style="border-left:4px solid {fc}">'
            f'<div class="ftitle"><span class="pill" style="background:{fc}">{html.escape(str(f.get("severity", "")))}</span> '
            f'<strong>{html.escape(str(f.get("category", "")))}: {html.escape(str(f.get("title", "")))}</strong></div>'
            f'<p>{html.escape(str(f.get("detail", "")))}</p>'
            f'<p class="action">Fix: {html.escape(str(f.get("action", "")))}</p>'
            f"</div>"
        )
    if not findings_html:
        findings_html = '<div class="card" style="border-left:4px solid #22c55e"><strong>No critical issues detected.</strong></div>'

    apps = [a for a in ((bui.get("week") or {}).get("apps") or (bui.get("day") or {}).get("apps") or []) if isinstance(a, dict)]
    max_en = max([max(0.0, _num(a.get("energy_pct"), 0.0)) for a in apps[:10]], default=1.0) or 1.0
    apps_rows = ""
    for a in apps[:10]:
        pct_num = max(0.0, _num(a.get("energy_pct"), 0.0))
        w = max(4, min(100, int(pct_num * 100.0 / max_en)))
        pct_disp = html.escape(str(a.get("energy_pct", 0)))
        fg_disp = html.escape(str(a.get("fg_min", 0)))
        bg_disp = html.escape(str(a.get("bg_min", 0)))
        apps_rows += (
            f'<tr><td>{html.escape(str(a.get("name", "unknown")))}</td>'
            f'<td><div class="bar-wrap"><div class="bar" style="width:{w}%"></div><span>{pct_disp}%</span></div></td>'
            f'<td>{fg_disp}m</td><td>{bg_disp}m</td></tr>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
<title>CellProbe Report - {html.escape(str(dev.get("product_type", "Device")))}</title>
<style>
  body{{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px;line-height:1.5}}
  .wrap{{max-width:960px;margin:0 auto}}
  .hdr{{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #334155;padding-bottom:16px;margin-bottom:24px;flex-wrap:wrap;gap:12px}}
  .pill{{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700;color:#0f172a}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}}
  .kpi{{background:#1e293b;padding:16px;border-radius:10px;border:1px solid #334155}}
  .kpi .lbl{{font-size:12px;color:#94a3b8;text-transform:uppercase}}
  .kpi .val{{font-size:24px;font-weight:700;margin-top:4px}}
  .card{{background:#1e293b;padding:14px 16px;border-radius:8px;margin-bottom:12px}}
  .action{{color:#38bdf8;font-size:14px;margin-bottom:0}}
  table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden}}
  th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #334155;font-size:14px}}
  th{{color:#94a3b8;font-size:12px;text-transform:uppercase}}
  .bar-wrap{{display:flex;align-items:center;gap:8px}}
  .bar{{height:10px;background:#38bdf8;border-radius:4px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div>
      <h1 style="margin:0;font-size:22px">CellProbe Diagnostics: {html.escape(str(dev.get("product_type", "Mobile Device")))}</h1>
      <div style="color:#94a3b8;font-size:13px">{html.escape(str(dev.get("os_version", "")))} | Generated {html.escape(str(evaluated.get("generated_at", "")))}</div>
    </div>
    <span class="pill" style="background:{badge_color};font-size:14px;padding:6px 16px">VERDICT: {html.escape(verdict)}</span>
  </div>
  <div class="grid">
    <div class="kpi"><div class="lbl">OS Health</div><div class="val">{html.escape(str(hw.get("ios_health_percent", "N/A")))}%</div></div>
    <div class="kpi"><div class="lbl">Cycle Count</div><div class="val">{html.escape(str(hw.get("cycle_count", "N/A")))}</div></div>
    <div class="kpi"><div class="lbl">Impedance (Ra)</div><div class="val">{html.escape(str(hw.get("weighted_ra_mohm", "N/A")))} m&#937;</div></div>
    <div class="kpi"><div class="lbl">Capacity (NCC)</div><div class="val">{html.escape(str(hw.get("nominal_charge_capacity_mah", "?")))} / {html.escape(str(hw.get("design_capacity_mah", "?")))} mAh</div></div>
    <div class="kpi"><div class="lbl">Free Storage</div><div class="val">{html.escape(str(dev.get("free_gb", "N/A")))} / {html.escape(str(dev.get("storage_gb", "N/A")))} GB</div></div>
    <div class="kpi"><div class="lbl">24h Wakes / Cell&le;2b</div><div class="val">{html.escape(str(sw.get("wakes_24h", "N/A")))} / {html.escape(str((sw.get("cellular") or {}).get("poor_signal_pct", 0)))}%</div></div>
  </div>
  <h2>Diagnostic Findings</h2>
  {findings_html}
  <h2>Top Energy Consumers</h2>
  <table><thead><tr><th>App</th><th>Energy Share</th><th>Foreground</th><th>Background</th></tr></thead>
  <tbody>{apps_rows or '<tr><td colspan="4">No app breakdown present in quick snapshot.</td></tr>'}</tbody></table>
</div>
</body>
</html>
"""
