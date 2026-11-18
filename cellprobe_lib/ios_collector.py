#!/usr/bin/env python3
"""
CellProbe Live iOS Collector (USB via pymobiledevice3).

Includes Windows usbmuxd Error 183 (SavePairRecord) bypass by reusing existing
Apple Lockdown pair records with autopair=False, and strictly read-only pulls
(erase=False).
"""

from __future__ import annotations

import asyncio
import json
import os
import plistlib
import re
import tempfile
from pathlib import Path
from typing import Any

from cellprobe_lib.ios_powerlog import _safe_int, analyze_ios_artifacts

_UDID_RE = re.compile(r"^(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{24,40})$")


class CollectorError(RuntimeError):
    """Clean, user-facing collection error without stack trace noise."""


def _validate_udid(udid: str) -> str:
    if not udid or not _UDID_RE.fullmatch(udid):
        raise CollectorError(f"Invalid iOS UDID format: {udid!r}")
    return udid


def _import_pymobiledevice3():
    try:
        from pymobiledevice3 import usbmux
        from pymobiledevice3.lockdown import create_using_usbmux
        from pymobiledevice3.services.crash_reports import CrashReportsManager
        from pymobiledevice3.services.diagnostics import DiagnosticsService
        return usbmux, create_using_usbmux, CrashReportsManager, DiagnosticsService
    except ImportError as exc:
        raise CollectorError(
            "pymobiledevice3 is required for live iPhone USB scanning. "
            "Install with: pip install pymobiledevice3"
        ) from exc


def _find_pair_record(udid: str) -> dict[str, Any] | None:
    safe_udid = _validate_udid(udid)
    candidates = [
        Path.home() / ".pymobiledevice3" / f"{safe_udid}.plist",
    ]
    if os.name == "nt":
        program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        candidates.append(program_data / "Apple" / "Lockdown" / f"{safe_udid}.plist")
    else:
        candidates.extend([
            Path("/var/db/lockdown") / f"{safe_udid}.plist",
            Path("/var/lib/lockdown") / f"{safe_udid}.plist",
        ])
    for p in candidates:
        if p.is_file() and not p.is_symlink():
            try:
                if p.stat().st_size > 512_000:
                    continue
                parsed = plistlib.loads(p.read_bytes())
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue
    return None


async def _list_devices_async() -> list[dict[str, Any]]:
    usbmux, _, _, _ = _import_pymobiledevice3()
    devices = await usbmux.list_devices()
    out = []
    for d in devices:
        out.append({
            "serial": d.serial,
            "connection_type": str(getattr(d, "connection_type", "")),
        })
    return out


def list_ios_usb_devices() -> list[dict[str, Any]]:
    try:
        return asyncio.run(_list_devices_async())
    except CollectorError:
        raise
    except Exception as exc:
        raise CollectorError(f"Failed to query USB iOS devices (is Apple Mobile Device Service running?): {exc}") from exc


async def _collect_async(udid: str | None, out_dir: Path, deep: bool) -> dict[str, Any]:
    usbmux, create_using_usbmux, CrashReportsManager, DiagnosticsService = _import_pymobiledevice3()
    devices = await usbmux.list_devices()
    usb_devs = [d for d in devices if "usb" in str(getattr(d, "connection_type", "")).lower()]
    if not usb_devs:
        raise CollectorError("No iPhone/iPad detected via USB. Connect cable, unlock device, and ensure iTunes/Apple Devices service is running.")

    if udid is not None:
        target_serial = _validate_udid(udid)
        if not any(str(d.serial).lower() == target_serial.lower() for d in usb_devs):
            raise CollectorError(f"Requested USB iOS device '{target_serial}' not found.")
    else:
        if len(usb_devs) > 1:
            raise CollectorError("Multiple USB iOS devices detected. Pass --udid <udid>.")
        target_serial = _validate_udid(str(usb_devs[0].serial))

    pair_record = _find_pair_record(target_serial)
    try:
        if pair_record is not None:
            try:
                lockdown = await create_using_usbmux(serial=target_serial, pair_record=pair_record, autopair=False)
            except Exception:
                lockdown = await create_using_usbmux(serial=target_serial, autopair=True)
        else:
            lockdown = await create_using_usbmux(serial=target_serial, autopair=True)
    except Exception as exc:
        raise CollectorError(
            f"Could not connect/pair with iOS device {target_serial}. "
            f"Unlock the iPhone and tap 'Trust This Computer'. Detail: {exc}"
        ) from exc

    out_dir.mkdir(parents=True, exist_ok=True)
    pulled_dir = out_dir / "pulled"
    pulled_dir.mkdir(exist_ok=True)

    device_meta: dict[str, Any] = {}
    quick_hw: dict[str, Any] = {}
    analytics_paths: list[Path] = []
    sysdiag_local: Path | None = None
    notes: list[str] = []

    try:
        info = lockdown.all_values or {}
        device_meta = {
            "DeviceName": info.get("DeviceName"),
            "ProductType": info.get("ProductType"),
            "HardwareModel": info.get("HardwareModel"),
            "ProductVersion": info.get("ProductVersion"),
            "BuildVersion": info.get("BuildVersion"),
            "UniqueDeviceID": target_serial,
        }

        async with DiagnosticsService(lockdown=lockdown) as diag:
            try:
                bat = await diag.get_battery() or {}
            except Exception as exc:
                bat = {}
                notes.append(f"Could not query live DiagnosticsService battery: {exc}")
            smart = {}
            try:
                smart = await diag.ioregistry(ioclass="AppleSmartBattery") or {}
            except Exception:
                smart = {}

            (out_dir / "battery_raw.json").write_text(json.dumps(bat, indent=2, default=str, allow_nan=False), encoding="utf-8")
            if smart:
                (out_dir / "smart_battery.json").write_text(json.dumps(smart, indent=2, default=str, allow_nan=False), encoding="utf-8")

            bd = smart.get("BatteryData") or {}
            wra_raw = bd.get("WeightedRa")
            wra = wra_raw[0] if isinstance(wra_raw, list) and wra_raw else _safe_int(wra_raw)
            quick_hw = {
                "CycleCount": bat.get("CycleCount") or smart.get("CycleCount"),
                "DesignCapacity": bat.get("DesignCapacity") or smart.get("DesignCapacity"),
                "NominalChargeCapacity": bat.get("NominalChargeCapacity") or smart.get("NominalChargeCapacity"),
                "FullChargeCapacity": smart.get("FullChargeCapacity"),
                "AppleRawMaxCapacity": smart.get("AppleRawMaxCapacity"),
                "Temperature": bat.get("Temperature") or smart.get("Temperature"),
                "Voltage": bat.get("Voltage") or smart.get("Voltage"),
                "InstantAmperage": bat.get("InstantAmperage") or smart.get("InstantAmperage"),
                "Serial": bat.get("Serial") or smart.get("Serial"),
                "WeightedRa": wra,
            }

        async with CrashReportsManager(lockdown=lockdown) as crm:
            try:
                files = await crm.ls("/", depth=3)
            except Exception as exc:
                files = []
                notes.append(f"Could not list crash logs: {exc}")

            analytics = sorted([f for f in files if "Analytics-" in f and (".ips" in f or ".synced" in f)])
            for af in analytics[-3:]:
                try:
                    await crm.pull(str(pulled_dir), entry=af, erase=False, progress_bar=False)
                    candidate = pulled_dir / Path(af).name
                    if candidate.exists():
                        analytics_paths.append(candidate)
                except Exception:
                    pass

            if deep:
                sysdiags = sorted(
                    f for f in files
                    if "sysdiagnose_" in f.lower() and "in_progress" not in f.lower() and (f.endswith(".tar.gz") or f.endswith(".tgz"))
                )
                if sysdiags:
                    latest = sysdiags[-1]
                    try:
                        await crm.pull(str(pulled_dir), entry=latest, erase=False, progress_bar=False)
                        cand = pulled_dir / Path(latest).name
                        if cand.exists():
                            sysdiag_local = cand
                    except Exception as exc:
                        notes.append(f"Could not pull sysdiagnose '{latest}': {exc}")
                else:
                    notes.append(
                        "No completed sysdiagnose archive found on device yet. "
                        "Trigger one on iPhone (Volume Up + Volume Down + Side Power for 1.5s, wait 5-10 min unlocked) and re-run --deep."
                    )
    finally:
        await lockdown.close()

    if sysdiag_local is not None:
        report = analyze_ios_artifacts(
            sysdiag_local,
            work_dir=out_dir / "extracted",
            quick_hardware=quick_hw,
            device_meta=device_meta,
            analytics_files=analytics_paths,
        )
    else:
        # Quick live capture only: use an empty scratch directory so stale prior extracts are ignored
        with tempfile.TemporaryDirectory(prefix="cellprobe_quick_") as quick_tmp:
            report = analyze_ios_artifacts(
                Path(quick_tmp),
                quick_hardware=quick_hw,
                device_meta=device_meta,
                analytics_files=analytics_paths,
            )
    report["collection_notes"] = notes
    return report


def collect_ios_live(udid: str | None = None, out_dir: Path | None = None, deep: bool = False) -> dict[str, Any]:
    target_dir = out_dir or (Path.cwd() / "cellprobe_ios_capture")
    try:
        return asyncio.run(_collect_async(udid=udid, out_dir=target_dir, deep=deep))
    except CollectorError:
        raise
    except Exception as exc:
        raise CollectorError(f"Live iOS collection failed: {exc}") from exc
