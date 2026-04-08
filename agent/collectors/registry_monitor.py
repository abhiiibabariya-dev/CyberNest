"""
CyberNest Agent -- Windows Registry Monitor Collector

Windows only: monitors persistence-related registry keys via winreg.
Watches HKLM\\...\\Run, RunOnce, HKCU\\...\\Run, HKLM\\...\\Services.
Emits ECS events on create / modify / delete of values.
"""

from __future__ import annotations

import asyncio
import platform
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from . import BaseCollector, ecs_base_event, register_collector

_DEFAULT_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
]

# Hive prefix -> winreg constant name
_HIVE_MAP = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKU": "HKEY_USERS",
    "HKEY_USERS": "HKEY_USERS",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
}

# Value type codes -> names
_REG_TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}

# Snapshot entry: (value_name, value_data_repr, value_type)
RegistryEntry = Tuple[str, str, int]


def _parse_key_path(key_path: str):
    """
    Parse a registry key path like ``HKLM\\SOFTWARE\\...`` and return
    (winreg_hive_constant, subkey_string).  Returns (None, None) on failure.
    """
    try:
        import winreg
    except ImportError:
        return None, None

    parts = key_path.replace("/", "\\").split("\\", 1)
    if len(parts) < 2:
        return None, None

    hive_str = parts[0].upper()
    subkey = parts[1]
    hive_name = _HIVE_MAP.get(hive_str)
    if hive_name is None:
        return None, None

    hive = getattr(winreg, hive_name, None)
    return hive, subkey


def _read_values(hive, subkey: str) -> Dict[str, RegistryEntry]:
    """Read all values from a registry key. Returns {value_name: (name, data_repr, type)}."""
    try:
        import winreg
    except ImportError:
        return {}

    result: Dict[str, RegistryEntry] = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            idx = 0
            while True:
                try:
                    name, data, dtype = winreg.EnumValue(key, idx)
                    # Convert data to a safe string representation
                    if isinstance(data, bytes):
                        data_repr = data.hex()
                    elif isinstance(data, list):
                        data_repr = "|".join(str(d) for d in data)
                    else:
                        data_repr = str(data)
                    result[name] = (name, data_repr, dtype)
                    idx += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    except OSError:
        pass
    return result


def _read_subkeys(hive, subkey: str) -> Set[str]:
    """Return the set of immediate subkey names under a registry key."""
    try:
        import winreg
    except ImportError:
        return set()

    result: Set[str] = set()
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            idx = 0
            while True:
                try:
                    sk_name = winreg.EnumKey(key, idx)
                    result.add(sk_name)
                    idx += 1
                except OSError:
                    break
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return result


@register_collector("registry_monitor")
class RegistryMonitorCollector(BaseCollector):
    """Monitor Windows registry keys for persistence changes."""

    async def _run(self) -> None:
        if platform.system() != "Windows":
            self.log.info("registry_monitor_skipped", reason="not_windows")
            return

        try:
            import winreg  # noqa: F401
        except ImportError:
            self.log.error("winreg_not_available")
            return

        keys: List[str] = self.config.get("keys", _DEFAULT_KEYS)
        interval: float = self.config.get("interval", 30.0)
        monitor_services: bool = self.config.get("monitor_services", True)

        # Initial snapshots: {key_path: {value_name: RegistryEntry}}
        value_snapshots: Dict[str, Dict[str, RegistryEntry]] = {}
        # For Services key we track subkeys instead
        subkey_snapshots: Dict[str, Set[str]] = {}

        for key_path in keys:
            hive, subkey = _parse_key_path(key_path)
            if hive is None:
                self.log.warning("invalid_registry_key", key=key_path)
                continue

            if "Services" in key_path and monitor_services:
                subkey_snapshots[key_path] = _read_subkeys(hive, subkey)
            else:
                value_snapshots[key_path] = _read_values(hive, subkey)

        self.log.info(
            "registry_monitor_started",
            value_keys=len(value_snapshots),
            service_keys=len(subkey_snapshots),
        )

        while self._running:
            await asyncio.sleep(interval)

            # Check value-based keys
            for key_path, prev_values in value_snapshots.items():
                hive, subkey = _parse_key_path(key_path)
                if hive is None:
                    continue

                current_values = _read_values(hive, subkey)

                # Detect new values
                for vname, entry in current_values.items():
                    if vname not in prev_values:
                        self._emit_registry_event(
                            action="created",
                            key_path=key_path,
                            value_name=vname,
                            value_data=entry[1],
                            value_type=_REG_TYPE_NAMES.get(entry[2], str(entry[2])),
                        )
                    elif prev_values[vname] != entry:
                        self._emit_registry_event(
                            action="modified",
                            key_path=key_path,
                            value_name=vname,
                            value_data=entry[1],
                            value_type=_REG_TYPE_NAMES.get(entry[2], str(entry[2])),
                            old_data=prev_values[vname][1],
                        )

                # Detect deleted values
                for vname in prev_values:
                    if vname not in current_values:
                        self._emit_registry_event(
                            action="deleted",
                            key_path=key_path,
                            value_name=vname,
                            value_data=prev_values[vname][1],
                            value_type=_REG_TYPE_NAMES.get(
                                prev_values[vname][2], str(prev_values[vname][2])
                            ),
                        )

                value_snapshots[key_path] = current_values

            # Check service-subkey-based keys
            for key_path, prev_subkeys in subkey_snapshots.items():
                hive, subkey = _parse_key_path(key_path)
                if hive is None:
                    continue

                current_subkeys = _read_subkeys(hive, subkey)

                for sk in current_subkeys - prev_subkeys:
                    self._emit_registry_event(
                        action="created",
                        key_path=f"{key_path}\\{sk}",
                        value_name="(subkey)",
                        value_data=sk,
                        value_type="subkey",
                    )

                for sk in prev_subkeys - current_subkeys:
                    self._emit_registry_event(
                        action="deleted",
                        key_path=f"{key_path}\\{sk}",
                        value_name="(subkey)",
                        value_data=sk,
                        value_type="subkey",
                    )

                subkey_snapshots[key_path] = current_subkeys

    def _emit_registry_event(
        self,
        *,
        action: str,
        key_path: str,
        value_name: str,
        value_data: str,
        value_type: str,
        old_data: str = "",
    ) -> None:
        ecs = ecs_base_event(
            event_kind="alert" if action == "created" else "event",
            event_category="registry",
            event_type={
                "created": "creation",
                "modified": "change",
                "deleted": "deletion",
            }.get(action, "info"),
            event_dataset="registry_monitor",
            agent_id=self.agent_id,
            agent_hostname=self.hostname,
            message=f"Registry {action}: {key_path}\\{value_name} = {value_data[:200]}",
        )

        ecs["event"]["action"] = f"registry_{action}"
        ecs["registry"] = {
            "key": key_path,
            "value": value_name,
            "data": {"strings": [value_data]},
            "data_type": value_type,
        }
        if old_data:
            ecs["registry"]["old_data"] = {"strings": [old_data]}

        self.emit(ecs)
