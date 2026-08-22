# pylint: disable=missing-function-docstring,unused-argument
from blint.lib.elf_abi import version_sort_key
from blint.lib.utils import parse_pe_manifest


def check_nx(f, metadata, rule_obj):  # noqa
    return metadata.get("has_nx") is not False


def check_pie(f, metadata, rule_obj):  # noqa
    return metadata.get("is_pie") is not False


def check_relro(f, metadata, rule_obj):  # noqa
    return metadata.get("relro") != "no"


def check_canary(f, metadata, rule_obj):  # noqa
    return metadata.get("has_canary") is not False


def check_rpath(f, metadata, rule_obj):  # noqa
    # Do not recommend setting rpath or runpath
    return not metadata.get("has_rpath") and not metadata.get("has_runpath")


def check_virtual_size(f, metadata, rule_obj):  # noqa
    if metadata.get("virtual_size"):
        virtual_size = metadata.get("virtual_size") / 1024 / 1024
        size_limit = 30
        if rule_obj.get("limit"):
            limit = rule_obj.get("limit")
            limit = limit.replace("MB", "").replace("M", "")
            if isinstance(limit, str) and rule_obj.get("limit").isdigit():
                size_limit = int(rule_obj.get("limit"))
        return virtual_size < size_limit
    return True


def check_authenticode(f, metadata, rule_obj):  # noqa
    if metadata.get("authenticode"):
        authenticode_obj = metadata.get("authenticode")
        vf = authenticode_obj.get("verification_flags", "").lower()
        return False if vf != "ok" else bool(authenticode_obj.get("cert_signer"))
    return True


def check_dll_characteristics(f, metadata, rule_obj):  # noqa
    res = []
    if metadata.get("dll_characteristics"):
        res += [
            c
            for c in rule_obj.get("mandatory_values", [])
            if c not in metadata.get("dll_characteristics")
        ]
    if res:
        res = ", ".join(res)

    return res or True


def check_codesign(f, metadata, rule_obj):  # noqa
    if metadata.get("code_signature"):
        code_signature = metadata.get("code_signature")
        return not code_signature or code_signature.get("available") is not False
    return True


def check_trust_info(f, metadata, rule_obj):  # noqa
    if metadata.get("resources"):
        if manifest := metadata.get("resources").get("manifest"):
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


def check_libc_portability(f, metadata, rule_obj):  # noqa
    # An image that reaches into C library internals is bound to the
    # implementation it was built against, so report the interfaces by name
    # rather than a bare pass or fail.
    abi = metadata.get("abi_analysis") or {}
    names = (abi.get("features") or {}).get("implementation_specific_imports") or []
    if not names:
        return True
    return ", ".join(names[:10])


def check_abi_floor(f, metadata, rule_obj):  # noqa
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


def check_runtime_loading(f, metadata, rule_obj):  # noqa
    # Libraries opened at runtime are absent from the dependency table, so an
    # image that loads them has a dependency surface no static list describes.
    recovered = metadata.get("recovered_dependencies") or []
    confident = [
        entry["name"] for entry in recovered if entry.get("confidence") in ("high", "medium")
    ]
    if not confident:
        return True
    return ", ".join(sorted(confident)[:10])


def check_link_closure(f, metadata, rule_obj):  # noqa
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


def check_search_path(f, metadata, rule_obj):  # noqa
    # A search path entry that is relative or world writable lets a directory
    # outside the package decide which library answers first.
    closure = metadata.get("link_closure") or {}
    risky = closure.get("risky_search_paths") or []
    if not risky:
        return True
    return ", ".join(f"{entry['kind']} {entry['path']} ({entry['issue']})" for entry in risky[:5])


def check_unused_dependencies(f, metadata, rule_obj):  # noqa
    # Only meaningful once symbols can be attributed to libraries; without that
    # every dependency looks unused.
    hygiene = metadata.get("link_hygiene") or {}
    unused = [entry["name"] for entry in hygiene.get("unused_dependencies") or []]
    if not unused:
        return True
    return ", ".join(unused[:10])


def check_undeclared_dependencies(f, metadata, rule_obj):  # noqa
    # A library supplying symbols without being declared is reached through
    # someone else's dependency list, which is not a contract.
    hygiene = metadata.get("link_hygiene") or {}
    undeclared = [entry["name"] for entry in hygiene.get("undeclared_dependencies") or []]
    if not undeclared:
        return True
    return ", ".join(undeclared[:10])


def check_security_property(f, metadata, rule_obj):  # noqa
    properties = metadata.get("security_properties", {})
    key = rule_obj.get("property_key")
    if not key:
        return True
    return properties.get(key) is True
