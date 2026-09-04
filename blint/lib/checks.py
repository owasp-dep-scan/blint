# pylint: disable=missing-function-docstring,unused-argument
from typing import Any

from blint.lib.elf_abi import version_sort_key
from blint.lib.utils import parse_pe_manifest


def check_nx(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    return metadata.get("has_nx") is not False


def check_wx_segments(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:  # noqa
    # A mapping that is writable and executable at the same time turns any
    # memory-write primitive into direct code execution, so the offending
    # segments are reported by name.
    names = [
        entry.get("name")
        for entry in metadata.get("wx_segments") or []
        if isinstance(entry, dict) and entry.get("name")
    ]
    if not names:
        return True
    return ", ".join(names[:5])


def check_pie(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    return metadata.get("is_pie") is not False


def check_relro(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    return metadata.get("relro") != "no"


def check_canary(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    return metadata.get("has_canary") is not False


def check_rpath(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    # Do not recommend setting rpath or runpath
    return not metadata.get("has_rpath") and not metadata.get("has_runpath")


def check_virtual_size(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    if virtual_size := metadata.get("virtual_size"):
        size_limit = 30
        if raw_limit := rule_obj.get("limit"):
            limit = str(raw_limit).replace("MB", "").replace("M", "")
            if limit.isdigit():
                size_limit = int(limit)
        return virtual_size / 1024 / 1024 < size_limit
    return True


def check_authenticode(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    if authenticode_obj := metadata.get("authenticode"):
        vf = authenticode_obj.get("verification_flags", "").lower()
        return False if vf != "ok" else bool(authenticode_obj.get("cert_signer"))
    return True


def check_dll_characteristics(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:  # noqa
    missing: list[str] = []
    if dll_characteristics := metadata.get("dll_characteristics"):
        missing += [
            c for c in rule_obj.get("mandatory_values", []) if c not in dll_characteristics
        ]
    if missing:
        return ", ".join(missing)
    return True


def check_codesign(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    if metadata.get("code_signature"):
        code_signature = metadata.get("code_signature")
        return not code_signature or code_signature.get("available") is not False
    return True


def check_trust_info(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:  # noqa
    if resources := metadata.get("resources"):
        if manifest := resources.get("manifest"):
            attribs_dict = parse_pe_manifest(manifest)
            if not attribs_dict:
                return True
            allowed_values = rule_obj.get("allowed_values", {})
            for k, v in allowed_values.items():
                manifest_k = attribs_dict.get(k)
                if isinstance(v, dict) and isinstance(manifest_k, dict):
                    for vk, vv in v.items():
                        if str(manifest_k.get(vk)).lower() != str(vv).lower():
                            return f"{vk}:{manifest_k.get(vk)}"
    return True


def check_libc_portability(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:  # noqa
    # An image that reaches into C library internals is bound to the
    # implementation it was built against, so report the interfaces by name
    # rather than a bare pass or fail.
    abi = metadata.get("abi_analysis") or {}
    names = (abi.get("features") or {}).get("implementation_specific_imports") or []
    if not names:
        return True
    return ", ".join(names[:10])


def check_abi_floor(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:  # noqa
    # Fails when the binary requires a runtime newer than the configured
    # baseline, which is the version the deployment target is known to ship.
    abi = metadata.get("abi_analysis") or {}
    required = abi.get("min_glibc_version")
    if not required:
        return True
    baseline = str(rule_obj.get("baseline_version") or "").strip()
    if not baseline:
        return True
    if version_sort_key(required) <= version_sort_key(baseline):
        return True
    return f"requires glibc {required}, baseline is {baseline}"


def check_runtime_loading(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:  # noqa
    # Libraries opened at runtime are absent from the dependency table, so an
    # image that loads them has a dependency surface no static list describes.
    recovered = metadata.get("recovered_dependencies") or []
    confident = [
        entry["name"] for entry in recovered if entry.get("confidence") in ("high", "medium")
    ]
    if not confident:
        return True
    return ", ".join(sorted(confident)[:10])


def check_link_closure(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:  # noqa
    # Only meaningful when closure resolution ran; an absent block means the
    # question was never asked, which is not a failure.
    closure = metadata.get("link_closure")
    if not closure:
        return True
    problems = [entry["name"] for entry in closure.get("missing") or []]
    if unresolved := closure.get("unresolved_symbol_count"):
        problems.append(f"{unresolved} unresolved symbols")
    if not problems:
        return True
    return ", ".join(problems[:10])


def check_search_path(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:  # noqa
    # A search path entry that is relative or world writable lets a directory
    # outside the package decide which library answers first.
    closure = metadata.get("link_closure") or {}
    risky = closure.get("risky_search_paths") or []
    if not risky:
        return True
    return ", ".join(f"{entry['kind']} {entry['path']} ({entry['issue']})" for entry in risky[:5])


def check_unused_dependencies(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:  # noqa
    # Only meaningful once symbols can be attributed to libraries; without that
    # every dependency looks unused.
    hygiene = metadata.get("link_hygiene") or {}
    unused = [entry["name"] for entry in hygiene.get("unused_dependencies") or []]
    if not unused:
        return True
    return ", ".join(unused[:10])


def check_undeclared_dependencies(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:  # noqa
    # A library supplying symbols without being declared is reached through
    # someone else's dependency list, which is not a contract.
    hygiene = metadata.get("link_hygiene") or {}
    undeclared = [entry["name"] for entry in hygiene.get("undeclared_dependencies") or []]
    if not undeclared:
        return True
    return ", ".join(undeclared[:10])


def check_security_property(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:  # noqa
    properties = metadata.get("security_properties", {})
    key = rule_obj.get("property_key")
    if not key:
        return True
    return properties.get(key) is True
