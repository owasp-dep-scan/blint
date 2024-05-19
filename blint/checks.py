# pylint: disable=missing-function-docstring,unused-argument
from blint.utils import parse_pe_manifest


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
