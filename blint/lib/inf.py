"""Windows driver package INF reader.

An INF tells Plug and Play which devices a driver package serves and what
installing it does: the services it creates, the co-installers and software it
runs, the files it copies and the registry values it writes. When Windows sees
a device whose hardware ID one of these packages declares, it can fetch the
package from Windows Update and install it as SYSTEM without asking anyone, so
the INF is the place where a package states what plugging in a matching device
does to the machine.

The reader reports declarations, not outcomes. It does not resolve which
decorated install section a particular device would select, so every fact is
"the package declares" rather than "this device installs". Everything returned
is plain JSON types.
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import functools
import os
import re
from typing import Any

# INFs are small text files; a file past this size is refused rather than
# read, so a hostile input cannot turn the reader into a memory sink.
MAX_INF_BYTES = 8 * 1024 * 1024
# Listing bounds. Every list keeps its full count beside the capped listing.
MAX_LISTED = 256
EXTERNAL_ID_SAMPLE = 8

# Buses a person can attach a device to from outside the machine. A package
# matched only by internal buses (PCI, ACPI, ROOT, SWD...) cannot be pulled in
# by plugging something in.
EXTERNAL_BUSES = frozenset(
    {
        "USB",
        "HID",
        "USBSTOR",
        "USBPRINT",
        "BTHENUM",
        "BTHLE",
        "BTHLEDEVICE",
        "SD",
        "1394",
        "PCMCIA",
    }
)

# Microsoft's own driver-framework co-installers. They ship with Windows or
# with the WDK redistributables and run no vendor logic.
_FRAMEWORK_COINSTALLER_RE = re.compile(
    r"^(wudfcoinstaller|wdfcoinstaller[\w$]*|wudfupdate_[\w$]*|winusbcoinstaller[\w$]*)\.dll$",
    re.IGNORECASE,
)

SERVICE_KINDS = {
    0x1: "kernel_driver",
    0x2: "file_system_driver",
    0x10: "win32_own_process",
    0x20: "win32_share_process",
}
START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}

# DIRIDs whose subdirectories standard users can create or modify files in
# under the default ACLs: the system drive root (24), ProgramData (16419) and
# Public Documents (16430). Code copied there can be replaced or planted
# beside by any local user.
WRITABLE_DIRIDS = {"24": "system_drive_root", "16419": "programdata", "16430": "public_documents"}
EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".exe",
        ".dll",
        ".sys",
        ".ocx",
        ".cpl",
        ".scr",
        ".com",
        ".drv",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
    }
)

# Registry locations that make Windows load or run something automatically,
# as (surface, subkey pattern, value names or None for any value).
_AUTOLOAD_SURFACES: tuple[tuple[str, re.Pattern, frozenset | None], ...] = (
    (
        "performance_library",
        re.compile(r"^system\\currentcontrolset\\services\\[^\\]+\\performance$"),
        frozenset({"library", "open", "collect", "close"}),
    ),
    ("print_monitor", re.compile(r"^system\\currentcontrolset\\control\\print\\monitors\\"), None),
    (
        "lsa_package",
        re.compile(r"^system\\currentcontrolset\\control\\lsa$"),
        frozenset({"notification packages", "security packages", "authentication packages"}),
    ),
    (
        "ifeo",
        re.compile(
            r"^software\\microsoft\\windows nt\\currentversion\\image file execution options\\"
        ),
        None,
    ),
    (
        "run_key",
        re.compile(
            r"^software\\(wow6432node\\)?microsoft\\windows\\currentversion\\run(once)?(ex)?$"
        ),
        None,
    ),
    (
        "appinit",
        re.compile(r"^software\\(wow6432node\\)?microsoft\\windows nt\\currentversion\\windows$"),
        frozenset({"appinit_dlls"}),
    ),
    (
        "winlogon",
        re.compile(r"^software\\microsoft\\windows nt\\currentversion\\winlogon$"),
        frozenset({"userinit", "shell", "taskman", "appsetup"}),
    ),
    (
        "appcert",
        re.compile(r"^system\\currentcontrolset\\control\\session manager\\appcertdlls$"),
        None,
    ),
    (
        "network_provider",
        re.compile(r"^system\\currentcontrolset\\control\\networkprovider\\order$"),
        None,
    ),
    (
        "time_provider",
        re.compile(r"^system\\currentcontrolset\\services\\w32time\\timeproviders\\"),
        None,
    ),
)
_REG_ROOTS = frozenset({"HKR", "HKLM", "HKCU", "HKCR", "HKU"})
_STRING_TOKEN_RE = re.compile(r"%([^%\r\n]*)%")
_DIRID_PREFIX_RE = re.compile(r"^%(-?\d+)%(\\(.*))?$")


def _decode(raw: bytes) -> tuple[str, str]:
    """The INF text and the encoding it was read as."""
    if raw[:2] == b"\xff\xfe":
        return raw[2:].decode("utf-16-le", "replace"), "utf-16-le"
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", "replace"), "utf-16-be"
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace"), "utf-8"
    if len(raw) >= 2 and raw[0] and not raw[1]:
        return raw.decode("utf-16-le", "replace"), "utf-16-le"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "ansi"


def _strip_comment(line: str) -> str:
    """The line up to the first semicolon outside a quoted string."""
    in_quote = False
    for index, char in enumerate(line):
        if char == '"':
            in_quote = not in_quote
        elif char == ";" and not in_quote:
            return line[:index]
    return line


def _logical_lines(text: str):
    """Comment-free lines with trailing-backslash continuations joined."""
    pending = ""
    for physical in text.splitlines():
        line = _strip_comment(physical).strip()
        if line.endswith("\\") and not line.endswith('\\"'):
            pending += line[:-1]
            continue
        line = (pending + line).strip()
        pending = ""
        if line:
            yield line
    if pending.strip():
        yield pending.strip()


def _split_fields(value: str) -> list[str]:
    """Comma-separated fields, honouring double quotes ("" is a literal quote)."""
    fields: list[str] = []
    current: list[str] = []
    in_quote = False
    index = 0
    while index < len(value):
        char = value[index]
        if char == '"':
            if in_quote and index + 1 < len(value) and value[index + 1] == '"':
                current.append('"')
                index += 1
            else:
                in_quote = not in_quote
        elif char == "," and not in_quote:
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    fields.append("".join(current).strip())
    return fields


def _split_entry(line: str) -> tuple[str | None, str]:
    """A ``key = value`` line as (lowercased key, value); (None, line) otherwise."""
    in_quote = False
    for index, char in enumerate(line):
        if char == '"':
            in_quote = not in_quote
        elif char == "=" and not in_quote:
            return line[:index].strip().lower(), line[index + 1 :].strip()
    return None, line


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


class _Inf:
    """The section table and string substitution for one INF."""

    def __init__(self, text: str):
        self.sections: dict[str, list[str]] = {}
        current: list[str] | None = None
        for line in _logical_lines(text):
            if line.startswith("[") and "]" in line:
                name = line[1 : line.index("]")].strip().lower()
                # Same-named sections are one section, in file order.
                current = self.sections.setdefault(name, [])
                continue
            if current is not None:
                current.append(line)
        self.strings: dict[str, str] = {}
        localized = sorted(name for name in self.sections if name.startswith("strings."))
        for name in ["strings", *localized]:
            for line in self.sections.get(name, []):
                key, value = _split_entry(line)
                if key and key not in self.strings:
                    fields = _split_fields(value)
                    self.strings[key] = fields[0] if fields else ""

    def substitute(self, value: str) -> str:
        """Expand %strkey% tokens; DIRID tokens (%13%) stay symbolic."""

        def replace(match: re.Match) -> str:
            token = match.group(1)
            if not token:
                return "%"
            if token.lstrip("-").isdigit():
                return match.group(0)
            return self.strings.get(token.lower(), match.group(0))

        return _STRING_TOKEN_RE.sub(replace, value)

    def fields(self, value: str) -> list[str]:
        return [self.substitute(field) for field in _split_fields(value)]

    def entries(self, section: str):
        """(key, fields) for each line of a section; key is None for bare lines."""
        for line in self.sections.get(section.lower(), []):
            key, value = _split_entry(line)
            if key is not None and key.split(",")[0].strip().upper() in _REG_ROOTS:
                # A registry line whose quoted data happens to contain "=".
                key, value = None, line
            yield key, self.fields(value)

    def directive_values(self, directive: str) -> list[list[str]]:
        """The field lists of every ``directive = ...`` line in any section."""
        found = []
        for name in self.sections:
            if name == "strings" or name.startswith("strings."):
                continue
            for key, fields in self.entries(name):
                if key == directive:
                    found.append(fields)
        return found

    def section_keys(self, section: str) -> dict[str, str]:
        """A key = value section as a dict of first fields (last value wins)."""
        values: dict[str, str] = {}
        for key, fields in self.entries(section):
            if key:
                values[key] = fields[0] if fields else ""
        return values


def _bus(device_id: str) -> str:
    if device_id.startswith("*"):
        return "*"
    return device_id.split("\\", 1)[0].upper()


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip())[-1] if path else ""


def _dirid_of(path: str) -> str | None:
    match = _DIRID_PREFIX_RE.match(path.strip())
    return match.group(1) if match else None


def _models(inf: _Inf) -> tuple[list[str], list[str]]:
    """Hardware IDs and compatible IDs from every models section."""
    hardware: dict[str, None] = {}
    compatible: dict[str, None] = {}
    for key, fields in inf.entries("manufacturer"):
        if not fields or not fields[0]:
            continue
        base = fields[0].lower()
        names = [base] + [
            f"{base}.{decoration.lower()}" for decoration in fields[1:] if decoration
        ]
        for section in names:
            for model_key, model_fields in inf.entries(section):
                if model_key is None or len(model_fields) < 2:
                    continue
                if model_fields[1]:
                    hardware.setdefault(model_fields[1], None)
                for extra in model_fields[2:]:
                    if extra:
                        compatible.setdefault(extra, None)
    return list(hardware), list(compatible)


def _services(inf: _Inf) -> list[dict[str, Any]]:
    services: dict[str, dict[str, Any]] = {}
    for fields in inf.directive_values("addservice"):
        if not fields or not fields[0] or len(fields) < 3:
            continue
        name = fields[0]
        values = inf.section_keys(fields[2])
        service_type = _to_int(values.get("servicetype"))
        start_type = _to_int(values.get("starttype"))
        binary = values.get("servicebinary", "")
        kind = SERVICE_KINDS.get((service_type or 0) & 0x3F) if service_type is not None else None
        entry: dict[str, Any] = {
            "name": name,
            "service_type": service_type,
            "kind": kind,
            "start_type": start_type,
            "start": START_TYPES.get(start_type) if start_type is not None else None,
            "binary": binary,
            "binary_name": _basename(binary),
        }
        if dirid := _dirid_of(binary):
            entry["binary_dirid"] = dirid
        if kind in ("win32_own_process", "win32_share_process"):
            entry["account"] = values.get("startname") or "LocalSystem"
        services.setdefault(name.lower(), entry)
    return list(services.values())


def _addreg_entries(inf: _Inf) -> list[dict[str, Any]]:
    """Every registry write declared through an AddReg directive."""
    referenced: dict[str, None] = {}
    for fields in inf.directive_values("addreg"):
        for section in fields:
            if section:
                referenced.setdefault(section.lower(), None)
    entries = []
    for section in referenced:
        for key, fields in inf.entries(section):
            if key is not None or not fields or fields[0].upper() not in _REG_ROOTS:
                continue
            padded = fields + [""] * (4 - len(fields))
            entries.append(
                {
                    "root": padded[0].upper(),
                    "subkey": padded[1],
                    "value_name": padded[2],
                    "flags": _to_int(padded[3]) if padded[3] else None,
                    "data": fields[4:],
                }
            )
    return entries


def _co_installers(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found: dict[tuple, dict[str, Any]] = {}
    for entry in entries:
        value_name = entry["value_name"].lower()
        subkey = entry["subkey"].replace("/", "\\").lower().strip("\\")
        if entry["root"] == "HKR" and value_name == "coinstallers32":
            scope = "device"
        elif entry["root"] == "HKLM" and subkey.endswith("control\\codeviceinstallers"):
            scope = "class"
        else:
            continue
        for item in entry["data"]:
            if not item:
                continue
            dll, _, entry_point = item.partition(",")
            dll = _basename(dll.strip())
            if not dll:
                continue
            co: dict[str, Any] = {
                "dll": dll,
                "scope": scope,
                "framework": bool(_FRAMEWORK_COINSTALLER_RE.match(dll)),
            }
            if entry_point.strip():
                co["entry_point"] = entry_point.strip()
            if scope == "class":
                co["class_guid"] = entry["value_name"]
            found.setdefault((dll.lower(), scope), co)
    return list(found.values())


def _registrations(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found = []
    for entry in entries:
        subkey = entry["subkey"].replace("/", "\\").lower().strip("\\")
        value_name = entry["value_name"].lower()
        if entry["root"] == "HKR" and subkey == "performance" and value_name == "library":
            # HKR inside a service's AddReg is that service's key.
            surface = "performance_library"
        elif entry["root"] == "HKLM":
            surface = next(
                (
                    name
                    for name, pattern, values in _AUTOLOAD_SURFACES
                    if pattern.search(subkey) and (values is None or value_name in values)
                ),
                None,
            )
            if surface is None:
                continue
        else:
            continue
        found.append(
            {
                "surface": surface,
                "root": entry["root"],
                "subkey": entry["subkey"],
                "value_name": entry["value_name"],
                "data": [str(item)[:260] for item in entry["data"][:4]],
            }
        )
    return found


def _software(inf: _Inf) -> list[dict[str, Any]]:
    software = []
    for fields in inf.directive_values("addsoftware"):
        if not fields or len(fields) < 3 or not fields[2]:
            continue
        values = inf.section_keys(fields[2])
        binary = values.get("softwarebinary", "")
        software.append(
            {
                "name": fields[0],
                "software_type": _to_int(values.get("softwaretype")),
                "binary": binary,
                "binary_name": _basename(binary),
                "arguments": values.get("softwarearguments", ""),
                "version": values.get("softwareversion", ""),
                "software_id": values.get("softwareid", ""),
            }
        )
    return software


def _destination(inf: _Inf, section: str, destinations: dict[str, list[str]]) -> dict[str, Any]:
    target = destinations.get(section.lower()) or destinations.get("defaultdestdir") or []
    dirid = target[0].strip() if target else ""
    subdir = target[1].strip() if len(target) > 1 else ""
    place: dict[str, Any] = {"dirid": dirid, "subdir": subdir}
    if dirid in WRITABLE_DIRIDS:
        place["writable"] = WRITABLE_DIRIDS[dirid]
    return place


def _copies(inf: _Inf) -> list[dict[str, Any]]:
    destinations = {
        key: fields for key, fields in inf.entries("destinationdirs") if key is not None
    }
    copies: dict[tuple, dict[str, Any]] = {}
    for fields in inf.directive_values("copyfiles"):
        for item in fields:
            if not item:
                continue
            if item.startswith("@"):
                files = [item[1:]]
                place = _destination(inf, "defaultdestdir", destinations)
            else:
                files = [
                    copy_fields[0]
                    for key, copy_fields in inf.entries(item)
                    if key is None and copy_fields and copy_fields[0]
                ]
                place = _destination(inf, item, destinations)
            for name in files:
                name = _basename(name)
                if not name:
                    continue
                entry = {"file": name, **place}
                if os.path.splitext(name)[1].lower() in EXECUTABLE_EXTENSIONS:
                    entry["executable"] = True
                copies.setdefault((name.lower(), place["dirid"], place["subdir"].lower()), entry)
    return list(copies.values())


def is_inf_file(path: str) -> bool:
    """True for a ``.inf`` file that carries the ``[Version]`` section every INF needs."""
    if not str(path).lower().endswith(".inf"):
        return False
    try:
        with open(path, "rb") as handle:
            head = handle.read(64 * 1024)
    except OSError:
        return False
    text, _ = _decode(head)
    return re.search(r"^\s*\[version\]", text, re.IGNORECASE | re.MULTILINE) is not None


def find_inf_files(src: str) -> list[str]:
    """Driver package INFs under a directory, or the path itself when it is one."""
    from blint.lib.utils import filter_ignored_dirs

    if os.path.isfile(src):
        return [os.path.abspath(src)] if is_inf_file(src) else []
    found = []
    for root, dirs, files in os.walk(src):
        filter_ignored_dirs(dirs)
        for name in files:
            if name.lower().endswith(".inf"):
                path = os.path.join(root, name)
                if is_inf_file(path):
                    found.append(os.path.abspath(path))
    return sorted(found)


def _listing(items: list, block: dict[str, Any], key: str) -> None:
    block[key] = items[:MAX_LISTED]
    if len(items) > MAX_LISTED:
        block[f"{key}_count"] = len(items)


def parse_inf(path: str) -> dict[str, Any]:
    """The ``inf`` block for one INF file."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return {"refused": f"unreadable: {e.__class__.__name__}"}
    if size > MAX_INF_BYTES:
        return {"refused": "inf_too_large", "bytes": size}
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as e:
        return {"refused": f"unreadable: {e.__class__.__name__}"}
    text, encoding = _decode(raw)
    inf = _Inf(text)
    version_keys = inf.section_keys("version")
    version = {
        key: version_keys[key]
        for key in ("signature", "class", "classguid", "provider", "driverver", "pnplockdown")
        if version_keys.get(key)
    }
    catalogs = sorted(
        {value for key, value in version_keys.items() if key.startswith("catalogfile") and value}
    )
    if catalogs:
        version["catalog_files"] = catalogs
    hardware_ids, compatible_ids = _models(inf)
    all_ids = hardware_ids + compatible_ids
    external = [device_id for device_id in all_ids if _bus(device_id) in EXTERNAL_BUSES]
    reg_entries = _addreg_entries(inf)
    block: dict[str, Any] = {
        "encoding": encoding,
        "version": version,
        "buses": sorted({_bus(device_id) for device_id in all_ids if device_id}),
        "pnp_matchable": bool(all_ids),
        "external_bus": bool(external),
        "external_ids": external[:EXTERNAL_ID_SAMPLE],
    }
    _listing(hardware_ids, block, "hardware_ids")
    _listing(compatible_ids, block, "compatible_ids")
    _listing(_services(inf), block, "services")
    _listing(_co_installers(reg_entries), block, "co_installers")
    _listing(_software(inf), block, "software")
    _listing(_registrations(reg_entries), block, "registrations")
    _listing(_copies(inf), block, "copies")
    return block


@functools.lru_cache(maxsize=256)
def _cached_inf(path: str, mtime_ns: int, size: int) -> dict[str, Any]:
    return parse_inf(path)


def _infs_in(folder: str) -> tuple[str, ...]:
    """The INF files in one directory, listed once while it is unchanged.

    Every binary in a directory asks for the same listing, and directories
    such as System32 hold thousands of binaries.
    """
    try:
        return _infs_listing(folder, os.stat(folder).st_mtime_ns)
    except OSError:
        return ()


@functools.lru_cache(maxsize=1024)
def _infs_listing(folder: str, mtime_ns: int) -> tuple[str, ...]:
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return ()
    return tuple(
        os.path.join(folder, name)
        for name in names
        if name.lower().endswith(".inf") and is_inf_file(os.path.join(folder, name))
    )


def inf_metadata(block: dict[str, Any], file_path: str) -> dict[str, Any]:
    """The analyzed metadata dict for one INF unit."""
    return {
        "name": os.path.basename(file_path),
        "file_path": file_path,
        "exe_type": "inf",
        "inf": block,
    }


def _system_service(service: dict[str, Any]) -> bool:
    account = str(service.get("account") or "").lower().replace(" ", "")
    return service.get("kind") in ("win32_own_process", "win32_share_process") and account in (
        "localsystem",
        ".\\localsystem",
        "ntauthority\\system",
    )


def privileged_roles(block: dict[str, Any], file_name: str | None = None) -> list[dict[str, Any]]:
    """What in this package runs as SYSTEM: services, co-installers, installer software.

    With ``file_name`` only the roles naming that file are returned. Microsoft's
    framework co-installers and kernel drivers are left out: the first run no
    vendor code, and the second are judged by the driver rules.
    """
    wanted = file_name.lower() if file_name else None
    roles: list[dict[str, Any]] = []
    for service in block.get("services") or []:
        if not _system_service(service):
            continue
        if wanted and str(service.get("binary_name") or "").lower() != wanted:
            continue
        roles.append(
            {
                "role": "system_service",
                "name": service.get("name"),
                "binary_name": service.get("binary_name"),
                "start": service.get("start"),
                "account": service.get("account"),
            }
        )
    for co in block.get("co_installers") or []:
        if co.get("framework"):
            continue
        if wanted and str(co.get("dll") or "").lower() != wanted:
            continue
        roles.append(
            {"role": "co_installer", "binary_name": co.get("dll"), "scope": co.get("scope")}
        )
    for software in block.get("software") or []:
        if software.get("software_type") != 1:
            continue
        if wanted and str(software.get("binary_name") or "").lower() != wanted:
            continue
        roles.append(
            {
                "role": "installer_software",
                "name": software.get("name"),
                "binary_name": software.get("binary_name"),
            }
        )
    return roles


def driver_package_context(
    binary_path: str, display_root: str | None = None
) -> dict[str, Any] | None:
    """The driver packages beside a binary that name it, or None.

    INFs in the binary's directory and its parent are read (packages often
    keep binaries in an architecture subdirectory). A package contributes only
    when it names this file as a service binary, co-installer, installer
    software or copied file, so an unrelated INF in the same folder says
    nothing about the binary.
    """
    file_name = os.path.basename(binary_path)
    if not file_name:
        return None
    directory = os.path.dirname(os.path.abspath(binary_path))
    candidates = list(_infs_in(directory))
    parent = os.path.dirname(directory)
    if parent != directory:
        candidates += _infs_in(parent)
    packages = []
    lowered = file_name.lower()
    for inf_path in candidates:
        try:
            stat = os.stat(inf_path)
        except OSError:
            continue
        block = _cached_inf(inf_path, stat.st_mtime_ns, stat.st_size)
        if block.get("refused"):
            continue
        roles = privileged_roles(block, file_name)
        copied = [
            copy
            for copy in block.get("copies") or []
            if str(copy.get("file") or "").lower() == lowered
        ]
        if not roles and not copied:
            continue
        # Relative to the binary (or the container root), so the context
        # carries no scan-host paths.
        try:
            shown = os.path.relpath(inf_path, display_root or directory)
        except ValueError:
            shown = os.path.basename(inf_path)
        package: dict[str, Any] = {
            "inf": shown,
            "provider": (block.get("version") or {}).get("provider"),
            "class": (block.get("version") or {}).get("class"),
            "external_bus": block.get("external_bus", False),
            "external_ids": block.get("external_ids") or [],
            "roles": roles,
        }
        if copied:
            package["copied_to"] = [
                {key: copy[key] for key in ("dirid", "subdir", "writable") if copy.get(key)}
                for copy in copied
            ]
        packages.append(package)
    return {"packages": packages} if packages else None
