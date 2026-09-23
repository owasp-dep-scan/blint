# pylint: disable=missing-function-docstring,unused-argument
from typing import Any

from blint.lib.elf_abi import version_sort_key
from blint.lib.provisioning import (
    application_identifier,
    entitlement,
    is_development,
    is_expired,
    is_wildcard,
)
from blint.lib.utils import parse_pe_manifest


def check_nx(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:
    # NX is a property of a loadable image. An ET_REL object (kernel
    # module, object file) has no program headers at all, so there is no
    # PT_GNU_STACK for has_nx to have read: F0 measured every ET_REL file
    # in the benign corpus firing a critical NX finding on exactly that
    # absence (readelf -l: no GNU_STACK, type REL). Metadata shapes without
    # elf_type keep the pre-gate behavior.
    if (
        str(metadata.get("binary_type") or "").upper() == "ELF"
        and str(metadata.get("elf_type") or "").upper() == "REL"
    ):
        return True
    return metadata.get("has_nx") is not False


def check_wx_segments(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
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


def check_objc_load_methods(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports classes whose ``+load`` runs before ``main``.

    Non-lazy classes are listed in ``__objc_nlclslist`` precisely because the
    runtime must execute their ``+load`` during image setup — code with no
    caller, which is an execution-order and persistence review surface rather
    than a defect.
    """
    objc = metadata.get("objc_metadata") or {}
    names = [entry.get("name") for entry in objc.get("nonlazy_classes") or [] if entry.get("name")]
    if not names:
        return True
    return ", ".join(sorted(names)[:10])


def check_tls_callbacks(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports TLS callbacks, which the loader runs before ``main``.

    The PE sibling of ``check_objc_load_methods``: TLS callbacks execute
    during process and thread setup with no caller in the code, which makes
    them a legitimate hook (CRT use, crash reporting) and the earliest code
    that runs in the process — a persistence and environment-tamper review
    surface. Evidence comes from the ``pre_main_execution`` summary; the
    resolved function names when the callback address matched a discovered
    function, the raw addresses otherwise.
    """
    pre_main = metadata.get("pre_main_execution") or {}
    callbacks = pre_main.get("tls_callbacks") or []
    names = [
        entry.get("function") or entry.get("address")
        for entry in callbacks
        if isinstance(entry, dict) and (entry.get("function") or entry.get("address"))
    ]
    if not names:
        return True
    return ", ".join(str(name) for name in names[:10])


def _is_main_executable(metadata: dict[str, Any]) -> bool:
    """Whether PIE is a meaningful question for this file.

    PIE is a property of main executables: a Mach-O dylib and an ELF shared
    object are position-independent or loaded at a slide by construction,
    and an ET_REL object has no load address at all. F0 measured the PIE
    rule firing on exactly those files 274 of 276 times on the benign
    tier-0 corpus, every finding false by construction (otool -hv filetype
    DYLIB, readelf -h type DYN/REL). The type fields are absent from
    metadata shapes older than this gate; those keep the pre-gate behavior
    (applicable) rather than silently widening the rule.
    """
    binary_type = str(metadata.get("binary_type") or "").upper()
    if binary_type == "MACHO":
        filetype = str(metadata.get("macho_filetype") or "").upper()
        return filetype in ("", "EXECUTE", "EXECUTABLE", "MH_EXECUTE")
    if binary_type == "ELF":
        elf_type = str(metadata.get("elf_type") or "").upper()
        if elf_type in ("", "EXEC"):
            return True
        return elf_type == "DYN" and bool(metadata.get("interpreter"))
    return True


def check_pie(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:
    if not _is_main_executable(metadata):
        return True
    return metadata.get("is_pie") is not False


def check_relro(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:
    return metadata.get("relro") != "no"


def check_canary(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:
    return metadata.get("has_canary") is not False


def check_rpath(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:
    # Do not recommend setting rpath or runpath
    return not metadata.get("has_rpath") and not metadata.get("has_runpath")


def check_virtual_size(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:
    if virtual_size := metadata.get("virtual_size"):
        size_limit = 30
        if raw_limit := rule_obj.get("limit"):
            limit = str(raw_limit).replace("MB", "").replace("M", "")
            if limit.isdigit():
                size_limit = int(limit)
        return virtual_size / 1024 / 1024 < size_limit
    return True


def check_authenticode(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
    """Reports files whose authenticity blint could not establish (02/B).

    The verdict follows the ``code_signature`` scope, and the finding states
    which of the three states it fired on:

    - ``scope: "catalog"`` — the file is signed through a catalog directory
      (--catalog-dir); the signer comes from the catalog. Never a finding.
    - ``scope: "none"`` with ``catalog_lookup: "negative"`` — the lookup
      was performed against a complete index and the file is in none of
      its catalogs: the only state from which "unsigned" may actually be
      claimed, so the finding names the directory the negative came from.
    - ``scope: "none"`` with ``catalog_lookup: "not_performed"`` (no
      directory supplied) or ``"index_incomplete"`` (the index refused or
      truncated catalogs) — "unsigned" was not determined, so the rule
      stays silent rather than manufacture the verdict (rule 11).
    - ``scope: "embedded"`` — the legacy verification below: a signature
      blob LIEF cannot verify (or a missing signer on it) is a finding.

    A block from metadata exported before the structured block existed
    takes the legacy path unchanged.
    """
    code_signature = metadata.get("code_signature")
    if isinstance(code_signature, dict):
        scope = code_signature.get("scope")
        if scope == "catalog":
            return True
        if scope == "none":
            lookup = code_signature.get("catalog_lookup")
            if lookup == "negative":
                return (
                    "no embedded signature and no matching member in the "
                    f"catalog directory {code_signature.get('catalog_directory')}"
                )
            # "not_performed" and "index_incomplete": an unsigned verdict
            # was not determined, so it is not reported.
            return True
    if authenticode_obj := metadata.get("authenticode"):
        vf = authenticode_obj.get("verification_flags", "").lower()
        return False if vf != "ok" else bool(authenticode_obj.get("cert_signer"))
    return True


def check_signature_not_timestamped(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports signatures that carry no countersignature timestamp (02/A.1).

    A signature without an RFC 3161 or PKCS#9 timestamp stops being
    verifiable the moment the signing certificate expires — with the
    short-lived certificates some CAs issue, that is days, not years. The
    verdict is per signature, nested ones included: they inherit the outer
    signature's timestamp and say so, so a dual-signed binary is not
    double-counted as untimestamped.
    """
    code_signature = metadata.get("code_signature")
    if not isinstance(code_signature, dict) or code_signature.get("parse_status") != "parsed":
        return True
    signatures = code_signature.get("signatures") or []
    untimestamped = [
        index + 1
        for index, signature in enumerate(signatures)
        if (signature.get("timestamp") or {}).get("present") is not True
    ]
    if not untimestamped:
        return True
    return f"signature(s) {untimestamped} of {code_signature.get('signature_count')} carry no timestamp"


def check_weak_signature_digest(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports files where no signature uses a modern digest (02/A.3).

    Dual signing is the normal shape for anything that must run on older
    Windows: a SHA-1 outer signature with a SHA-256 one nested inside it.
    The block's ``weak_digest_only`` is computed over every signature
    including nested ones, so only a binary with no modern digest anywhere
    is reported — the outer SHA-1 alone would flag ordinary modern
    binaries. It is ``None`` when a truncated walk could not see every
    signature, and an undecided verdict is not a finding.
    """
    code_signature = metadata.get("code_signature")
    if not isinstance(code_signature, dict) or code_signature.get("parse_status") != "parsed":
        return True
    if code_signature.get("weak_digest_only") is not True:
        return True
    return "no signature uses SHA-256 or stronger"


def _parsed_signature_block(metadata: dict[str, Any]) -> dict | None:
    """The ``code_signature`` block when its facts were actually parsed."""
    code_signature = metadata.get("code_signature")
    if isinstance(code_signature, dict) and code_signature.get("parse_status") == "parsed":
        return code_signature
    return None


def _deciding_signer(block: dict) -> dict:
    """The signer of the signature the block's ``signing_class`` came from.

    Every class rule names the same signature the class was derived from —
    ``signing_class_signature`` says which, and naming some other signer in
    the finding would describe a signature the verdict is not about.
    """
    signatures = block.get("signatures") or []
    index = block.get("signing_class_signature", 0)
    if index >= len(signatures):
        return {}
    return signatures[index].get("signer") or {}


def check_self_signed(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
    """Reports a signature whose signer certificate is its own root (02/C).

    A self-signed signer vouches for itself: no certificate authority
    stands behind the identity the signature states, so nothing anchors it
    to a publisher. Common for internal test signing — and for malware
    that wants a "signed" look — which is why the finding names the
    signer instead of pretending to know which. The verdict follows the
    block's ``signing_class``: withheld when the walk was truncated, so a
    sample can never decide it.
    """
    block = _parsed_signature_block(metadata)
    if not block or block.get("signing_class") != "self_signed":
        return True
    signer = _deciding_signer(block)
    return f"self-signed signer ({signer.get('cn')}): no certificate authority vouches for the identity"


def check_signature_unknown_root(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports a complete chain terminating outside the shipped root
    snapshot (02/C).

    The signature blob carried its whole chain up to a self-signed root,
    and that root's SHA-256 fingerprint is not in blint's shipped anchor
    snapshot (``pe_roots.yml`` — the trusted roots hashed from a Windows
    store, with provenance, at a stated date). This is a statement about
    the file, not a trust verdict: blint performs no trust validation and
    consults no live store, so a root added to Windows after the snapshot,
    or absent from it, reads the same way. A chain that stops below the
    root — the normal Authenticode shape — reports nothing here, because
    absence of a root in the blob is not evidence about the root (rule
    11). The verdict follows ``signing_class`` and is withheld when the
    walk was truncated.
    """
    block = _parsed_signature_block(metadata)
    if not block or block.get("signing_class") != "unknown_root":
        return True
    signature = block["signatures"][block.get("signing_class_signature", 0)]
    return (
        "chain terminates at self-signed root "
        f"{signature.get('chain_terminates_at')} whose fingerprint is outside "
        "the shipped root snapshot"
    )


def check_kernel_signing_class(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports the kernel-mode code-signing class (02/C), informational.

    The signer carries the kernel-mode code signing EKU
    (``1.3.6.1.4.1.311.61.1.1``), meaning the binary is signed for (or
    claims to be signed for) execution as a kernel component. This is a
    posture fact for the analyst — kernel code runs with the operating
    system's privileges — not a defect claim, and the driver lane consumes
    it directly.

    It reads the EKU rather than ``signing_class == "kernel_mode"``: a
    chain fact outranks the leaf's claims in the class, so a kernel-EKU
    driver whose chain terminates outside the shipped snapshot classes as
    ``unknown_root`` — and that is precisely the file whose kernel signing
    the driver lane must still see. The class must have been *determined*
    for this to speak, which keeps the truncation discipline: a walk that
    hit its window yields no class and no finding here.
    """
    block = _parsed_signature_block(metadata)
    if not block or not block.get("signing_class"):
        return True
    if "kernelModeCodeSigning" not in (_deciding_signer(block).get("eku") or []):
        return True
    return f"kernel-mode code signing ({_deciding_signer(block).get('cn')})"


_PUBLISHER_CACHE: dict | None = None


def _publisher_table() -> dict:
    """The claimable-publisher identity table (pe_publisher_identities.yml).

    Generated/judged data with provenance, never hard-coded names: the
    signer-mismatch rule arbitrates only publishers listed here, because a
    name difference between two unknown identities is not a tampering
    signal (the Sysinternals measurement that decided the comparison is
    recorded in the table header)."""
    global _PUBLISHER_CACHE
    if _PUBLISHER_CACHE is None:
        _PUBLISHER_CACHE = _load_yaml_data("pe_publisher_identities.yml")
    return _PUBLISHER_CACHE


def _load_yaml_data(filename: str) -> dict:
    import importlib.resources

    import yaml

    try:
        with importlib.resources.files("blint.data").joinpath(filename).open(
            "r", encoding="utf-8"
        ) as handle:
            return yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):
        return {}


def check_signer_mismatch(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports a VERSIONINFO company claim the signature does not back (02/C).

    Fires only in the impersonation direction: ``CompanyName`` claims a
    publisher from the identity table, and the signature's signer carries
    none of that publisher's identity tokens. That is how a signed-but-
    repurposed binary looks — re-signed by someone else with the victim's
    version strings left in place. The reverse direction is deliberately
    not a finding: Microsoft signs the Sysinternals suite whose
    CompanyName still says "Sysinternals", and the Python Software
    Foundation signs the OpenSSL DLLs it redistributes — measured 152 of
    178 tier-0/1 files with both facts differ benignly, so a symmetric
    comparison would be wrong, not the corpus. Companies absent from the
    table are never arbitrated, and a missing signer or CompanyName
    determines nothing (rule 11).
    """
    block = _parsed_signature_block(metadata)
    if not block:
        return True
    signer = next(
        (
            sig.get("signer") or {}
            for sig in block.get("signatures") or []
            if (sig.get("signer") or {}).get("cn")
        ),
        {},
    )
    signer_identity = signer.get("o") or signer.get("cn") or ""
    if not signer_identity:
        return True
    version_info = metadata.get("version_info") or {}
    tables = version_info.get("strings") or {}
    companies = sorted(
        {table.get("CompanyName") for table in tables.values() if table.get("CompanyName")}
    )
    if not companies:
        return True
    publishers = _publisher_table().get("publishers") or {}
    for company in companies:
        lowered = company.lower()
        for publisher, facts in publishers.items():
            claim_tokens = facts.get("claim_tokens") or []
            if not any(token in lowered for token in claim_tokens):
                continue
            # The claim is present; the signer must carry the publisher.
            signer_tokens = facts.get("signer_tokens") or []
            if any(token in signer_identity.lower() for token in signer_tokens):
                continue
            return (
                f"CompanyName {company!r} claims the {publisher} publisher, but the "
                f"signature signer is {signer_identity!r}"
            )
    return True


def _host_plugin_contracts(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """The matched host-plugin contracts, or [] when there is nothing to say.

    The block exists only when a contract matched, so an absent block is
    "no evidence of a plugin contract", never "verified not a plugin":
    a binary whose export table blint could not read produces no block and
    an ``export_table_unreadable`` degradation instead (rules 14/32).
    """
    block = metadata.get("host_plugin")
    if isinstance(block, dict):
        contracts = block.get("contracts")
        if isinstance(contracts, list) and contracts:
            return [c for c in contracts if isinstance(c, dict)]
    return []


def check_privileged_host_plugin(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports the privileged-host plugin contracts the export set satisfies.

    This is context, not an accusation: legitimate audio, print and
    authentication software looks exactly like this, which is why the
    severity is informational. What the finding names is the consequence -
    a DLL satisfying one of these export contracts is one admin
    registration away from being loaded into the named host on every boot
    or logon, with no per-load prompt. The contract table and its
    measurement live in blint/data/pe_host_plugin_contracts.yml; bare COM
    in-proc exports never fire this (45% of a stock System32 exports the
    pair), and the two COM contracts require an in-binary registration
    reference and say so in their evidence.
    """
    contracts = _host_plugin_contracts(metadata)
    if not contracts:
        return True
    described = []
    for contract in contracts:
        hosts = contract.get("host_process") or "its host process"
        described.append(f"{contract.get('id')} ({hosts})")
    return "plugin contracts satisfied: " + "; ".join(described)


def _macos_host_plugin(metadata: dict[str, Any]) -> dict[str, Any] | None:
    """The macOS host_plugin block, or None (the PE block carries contracts)."""
    block = metadata.get("host_plugin")
    if isinstance(block, dict) and block.get("kind") and not block.get("contracts"):
        return block
    return None


def check_macos_host_plugin(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports that this bundle is a plugin loaded into a named host (M1.1).

    Context for a reviewer, not an accusation: legitimate audio, camera and
    indexing software looks exactly like this, which is why the severity is
    informational. What the finding names is the consequence the bundle
    suffix + location carry - the host process the plugin loads into, that
    host's privilege, and how the plugin got there (a ``.driver`` installs
    with an administrator password and no dialog; a ``.systemextension`` /
    ``.dext`` activates through a one-time user-approval dialog). The
    block is present only when the kind names a host, so an absent block
    reads as "no host determined from this bundle", never as "verified not
    a plugin".
    """
    block = _macos_host_plugin(metadata)
    if not block:
        return True
    scope = block.get("install_scope") or "no install scope determined (bundle seen out of context)"
    described = (
        f"{block.get('title')} ({block.get('kind')}), loaded into "
        f"{block.get('host')}; host privilege: {block.get('host_privilege')}; "
        f"activation: {block.get('activation')}; install scope: {scope}"
    )
    if app := block.get("containing_app"):
        described += f"; contained by application {app}"
    return described


def check_audio_plugin_network(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports an Audio Server Plug-In declaring network access (M1.1).

    The finding is about a declaration, not observed behaviour: the
    bundle's Info.plist carries ``AudioServerPlugIn_Network`` and blint
    read it statically - blint did not watch the plugin use the network.
    The declaration is a request for the audio plugin host to extend the
    plugin's restrictive base sandbox with network access, which the host
    honours. Measured on a stock system (macOS 15.8: 0 of the 12 Apple HAL
    plugins declare it, including Apple's own network-audio AirPlay.driver
    and AppleAVBAudio.driver, which reach the network through companion
    processes over Mach IPC instead), so the rule is quiet by construction
    on the benign population.
    """
    block = _macos_host_plugin(metadata)
    if not block:
        return True
    declarations = block.get("declarations") or {}
    if declarations.get("network") is not True:
        return True
    return (
        "the bundle's Info.plist declares AudioServerPlugIn_Network - a request "
        "that the audio plugin host extend this plugin's sandbox to allow "
        "network access. This is a declaration blint read from the bundle, not "
        "behaviour it observed; blint did not watch the plugin open any "
        "network connection"
    )


def check_unsigned_host_plugin(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports a host-plugin contract not vouched for by any signer (04/F, M1.1).

    The PE form follows the W2.4 ``signing_class`` exactly: it fires on
    ``unsigned``, ``self_signed`` and ``unknown_root``, and stays silent
    when the class is absent (undetermined - blint's default invocation
    performs no catalog lookup, and absence of a class is neither signed
    nor unsigned) or when the walk was truncated.

    The macOS form (M1.1) fires on a plugin bundle in a system or
    machine-wide install scope that is neither an Apple platform binary
    nor Developer-ID-signed: auto-loaded into the named host on every
    boot, installed once, vouched for by nobody. It stays silent when the
    signature could not be determined (no blob, or a parse failure), when
    the signature is fine but its identity is something blint cannot
    classify, and when the bundle has no install scope - a plugin in a
    downloads folder is not installed anywhere yet, and the finding would
    be a verdict blint did not determine. Trust follows the primary
    slice's parsed signature, the slice whose facts the metadata top level
    carries.
    """
    contracts = _host_plugin_contracts(metadata)
    if contracts:
        block = _parsed_signature_block(metadata)
        signing_class = (block or {}).get("signing_class")
        if signing_class not in ("unsigned", "self_signed", "unknown_root"):
            return True
        contract_ids = ", ".join(sorted({str(c.get("id")) for c in contracts}))
        if signing_class == "unsigned":
            detail = "no signature: a performed, complete catalog lookup found nothing"
        elif signing_class == "self_signed":
            detail = "self-signed: the signer vouches for itself, no authority stands behind it"
        else:
            detail = "chain terminates outside the shipped root snapshot"
        return (
            f"auto-loaded plugin contract(s) {contract_ids} with signing class "
            f"{signing_class} ({detail})"
        )
    macos_block = _macos_host_plugin(metadata)
    if not macos_block:
        return True
    if macos_block.get("install_scope") not in ("system", "machine"):
        return True
    detail = _macos_plugin_identity_verdict(metadata)
    if detail is None:
        return True
    return (
        f"{macos_block.get('title')} in {macos_block.get('install_scope')}-wide install "
        f"scope with no identity vouching for it: {detail}. Auto-loaded into "
        f"{macos_block.get('host')} - {macos_block.get('activation')} - and "
        "nothing stands behind the code that runs there"
    )


def _macos_plugin_identity_verdict(metadata: dict[str, Any]) -> str | None:
    """Why nothing vouches for this Mach-O, or None when undetermined.

    Reads the primary slice's ``code_signature`` block: an Apple platform
    binary (any CodeDirectory carrying a platform identifier, the fact
    ``codesign -dv`` prints as ``Platform identifier``) and a Developer-ID
    signer (the CMS signer common name, what ``spctl -a -vv`` prints as
    the origin) both vouch. An absent signature, an ad-hoc or
    linker-signed blob, and a parsed signature whose signer is neither of
    those do not. A blob blint could not parse determines nothing.
    """
    signature = metadata.get("code_signature")
    if not isinstance(signature, dict):
        return None
    status = signature.get("parse_status")
    if signature.get("available") is False or status == "absent":
        return "the binary carries no code signature at all"
    # A present blob blint could not parse (or a shape with no status at
    # all) determines nothing: undetermined is neither signed nor unsigned.
    if status != "parsed":
        return None
    superblob = signature.get("superblob")
    if not isinstance(superblob, dict):
        return None
    for directory in superblob.get("code_directories") or []:
        if isinstance(directory, dict) and directory.get("platform_id"):
            return None
    provenance = superblob.get("provenance")
    cms = superblob.get("cms")
    if provenance in ("adhoc", "linker_signed"):
        return f"signed {provenance.replace('_', ' ')} - a signature with no identity behind it"
    if provenance == "cms_signed" and isinstance(cms, dict):
        signer_cn = cms.get("signer_cn")
        if isinstance(signer_cn, str) and signer_cn:
            if "Developer ID" in signer_cn:
                return None
            return (
                f"signed by {signer_cn!r}, which is neither an Apple platform "
                "identity nor a Developer ID certificate"
            )
    return None


def check_lsa_plugin(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports the lsass.exe contract that sees passwords in plaintext.

    Only the password-filter / notification-package exports fire this:
    those are the entry points the LSA calls with the account's plaintext
    password on every change, which is what makes the contract the
    classic credential-capture implant surface. ``SpLsaModeInitialize``
    deliberately does not: measured over a full System32 it is on every
    core logon protocol (msv1_0, kerberos, schannel, wdigest, pku2u,
    negoexts, cloudap, TSpkg, SFAPM - nine DLLs), and a high-severity
    finding on the OS's own authentication stack would be noise wearing a
    rule's name; that contract is reported by
    CHECK_PRIVILEGED_HOST_PLUGIN and feeds CHECK_UNSIGNED_HOST_PLUGIN.
    The narrowing and its measurement are recorded in
    blint/data/pe_host_plugin_contracts.yml.
    """
    contracts = _host_plugin_contracts(metadata)
    password_filter = next(
        (c for c in contracts if c.get("id") == "lsa_password_filter"), None
    )
    if not password_filter:
        return True
    exports = ", ".join(password_filter.get("matched_exports") or [])
    return (
        f"password filter exports ({exports}) for lsass.exe (SYSTEM, protected): "
        "loaded via Lsa Notification Packages it receives every account "
        "password change in plaintext"
    )


def check_known_vulnerable_driver(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports a binary whose digest pins it in the vulnerable-driver
    snapshot (04/C.4).

    The snapshot (loldrivers.io plus the Microsoft recommended driver block
    rules) ships as data with provenance; refreshing it is a data PR and
    there is no network call at scan time. Matching is exact-hash only -
    SHA-256 or MD5 - because driver filenames collide across vendors and
    the accusation is specific enough that a name match would be a false
    positive by construction. The finding names the driver entry and the
    source that knows it, so a reviewer can go from blint's line to the
    published advisory directly.
    """
    block = metadata.get("vulnerable_driver")
    if not isinstance(block, dict):
        return True
    matches = block.get("matches") or []
    if block.get("lookup_status") != "matched" or not matches:
        return True
    named = []
    for match in matches[:3]:
        named.append(f"{match.get('driver')} ({match.get('source')}, by {match.get('field')})")
    return "known vulnerable driver: " + "; ".join(named)


def _driver_block(metadata: dict[str, Any]) -> dict[str, Any] | None:
    """The W5.1 ``driver`` block when this image is a driver."""
    block = metadata.get("driver")
    if isinstance(block, dict):
        return block
    return None


def check_hvci_compatible(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
    """Reports the HVCI conditions a driver fails, with per-condition
    evidence (04/B).

    Memory integrity (HVCI) refuses kernel drivers whose image cannot be
    mapped safely at randomized addresses: x86 code, writable+executable
    pages, sub-page section alignment, stripped relocations. Microsoft's
    own checker is a documented ruleset, so the finding names *which*
    condition failed and why - "not compatible" alone says nothing a
    reviewer can act on. Measured before this rule shipped (ground rule
    34): all 330 drivers on the VM's full System32\\drivers pass every
    condition, so a failure is a signal, not noise. Conditions whose
    source could not be read are ``undetermined``, not failed, and an
    image with any undetermined condition states the gap instead of a
    verdict.
    """
    driver = _driver_block(metadata)
    if not driver:
        return True
    hvci = driver.get("hvci_compatibility") or {}
    failed = hvci.get("failed_conditions") or []
    if failed:
        evidence = hvci.get("failure_evidence") or {}
        detail = "; ".join(
            f"{condition}: {evidence.get(condition, 'failed')}" for condition in failed[:5]
        )
        return f"HVCI-incompatible ({detail})"
    # An undetermined condition does NOT fire this rule. The rule is titled
    # "Driver Incompatible with HVCI" at high severity; rendering "blint
    # could not read the section characteristics" under that title is the
    # two-outcomes-one-rule conflation ground rule 14 forbids, and it would
    # accuse a driver of a violation blint never observed. The gap is not
    # swallowed either: hvci_compatibility.compatible is null and
    # undetermined_conditions names each one, which is where a blind spot
    # belongs (rule 32).
    return True


def check_boot_start_integritycheck(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports a boot-start driver without /INTEGRITYCHECK (04/B).

    ``/INTEGRITYCHECK`` (FORCE_INTEGRITY) is mandatory for boot-start
    drivers - the images winload loads before the kernel can enforce
    signature policy any other way. Boot-start-ness is determined
    statically exactly once: the WINDOWS_BOOT_APPLICATION subsystem. For
    every other driver, StartType lives in the registry blint does not
    read, so the fact is undetermined and this rule stays silent rather
    than assume (rule 11). The flag's absence must be *computed* - a
    driver whose DLL-characteristics source was absent is undetermined
    and passes silently (the key is then not in kernel_hardening).
    """
    driver = _driver_block(metadata)
    if not driver:
        return True
    hardening = driver.get("kernel_hardening") or {}
    if hardening.get("boot_start") is not True:
        return True
    if hardening.get("force_integrity") is False:
        return "/INTEGRITYCHECK (FORCE_INTEGRITY) is absent on a boot-start driver"
    # force_integrity absent from the block means the DLL-characteristics
    # source was unreadable: undetermined, not absent - the rule stays
    # silent (ground rule 32).
    return True


def check_msix_restricted_capability(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports the restricted capabilities an MSIX/Appx manifest declares.

    Restricted capabilities (the ``rescap`` namespace — ``runFullTrust``,
    ``allowElevation``, ``broadFileSystemAccess`` and friends) are the
    declarations that take a packaged application out of the app container:
    each one is named in the finding because each names a different
    capability surface. The verdict follows the declared facts only —
    blint performs no review of the package's store approval — and reads
    the counted total, so a manifest past the listing cap still fires (the
    W3.2 lesson: a listing bound must not become a detection boundary).
    """
    container = metadata.get("container")
    if not isinstance(container, dict):
        return True
    restricted = container.get("capabilities", {}).get("restricted") or []
    counted = container.get("restricted_capability_count") or 0
    if not restricted and not counted:
        return True
    if not restricted:
        # Counted but unlisted. The engine treats any string as a finding,
        # so returning the empty join would have titled it "(...)" with
        # nothing inside — a finding that names nothing (rule 11). The
        # count is what blint determined, so the count is what it says.
        return f"{counted} restricted capabilities"
    return ", ".join(str(name) for name in restricted[:10])


def check_dll_characteristics(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports mandatory DLL characteristics the image does not carry.

    Membership is tested against the structured ``flags`` list decoded from
    the numeric bitfield (pe_constants), never against rendered enum text:
    LIEF 1.0 renders DLL_CHARACTERISTICS members as integers (V1), which made
    every value read as missing. The joined-string fallback keeps metadata
    exported before the structured block existed (parse cache) working.

    An image whose bitfield is zero carries none of the mandatory values, so
    it reports all of them. Keying the decision off the joined string instead
    would let the least hardened PE of all pass silently.
    """
    missing: list[str] = []
    structured = metadata.get("dll_characteristics_structured")
    mandatory_values = rule_obj.get("mandatory_values", [])
    if isinstance(structured, dict) and "flags" in structured:
        flag_names = {str(v).upper() for v in structured.get("flags") or []}
        missing += [c for c in mandatory_values if str(c).upper() not in flag_names]
    elif dll_characteristics := metadata.get("dll_characteristics"):
        missing += [c for c in mandatory_values if c not in dll_characteristics]
    if missing:
        return ", ".join(missing)
    return True


def check_codesign(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:
    if metadata.get("code_signature"):
        code_signature = metadata.get("code_signature")
        return not code_signature or code_signature.get("available") is not False
    return True


def _profile_or_clean(metadata: dict[str, Any]) -> dict[str, Any] | None:
    """The bundle's decoded provisioning profile, or None when nothing is judged.

    A binary without an embedded profile is clean for the profile rules: the
    absence of a profile is the ordinary case (App Store distribution), and
    an unparseable profile is reported through its own ``parse_status``
    rather than guessed at.
    """
    profile = metadata.get("provisioning_profile")
    if isinstance(profile, dict) and profile.get("parse_status") == "parsed":
        return profile
    return None


def check_profile_expired(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Fails when the embedded profile's validity window closed.

    An expired profile stops the app from launching (or blocks distribution
    in the enterprise case), so this reports the date it lapsed.
    """
    profile = _profile_or_clean(metadata)
    if profile is None:
        return True
    if is_expired(profile):
        return f"profile '{profile.get('name')}' expired {profile.get('expires')}"
    return True


def check_profile_development(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Fails when the shipped profile provisions a development build.

    A development profile signs ``get-task-allow``: any process entitled to
    debug can attach to the shipping binary, and the app only runs on the
    devices listed in the profile. Release builds must not carry one.
    """
    profile = _profile_or_clean(metadata)
    if profile is None:
        return True
    if is_development(profile):
        detail = f"get-task-allow in profile '{profile.get('name')}'"
        if entitlement(profile, "aps-environment") == "development":
            detail += ", development APNs environment"
        return detail
    return True


def check_profile_wildcard(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Fails when the profile's application identifier is a wildcard.

    A ``<team-id>.*`` identifier lets the signing identity cover any bundle
    ID, which weakens what the signature attests.
    """
    profile = _profile_or_clean(metadata)
    if profile is None:
        return True
    if is_wildcard(profile):
        return f"wildcard application identifier '{application_identifier(profile)}'"
    return True


def check_trust_info(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
    if (resources := metadata.get("resources")) and (manifest := resources.get("manifest")):
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


def check_build_path_leak(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    """Reports a CodeView PDB reference that leaks a build-machine path.

    The PDB path is embedded so the linker can find symbols; it names the
    build agent's directory tree, and CI runs leak usernames and internal
    hostnames with it (``D:\\a\\1\\b\\...`` is Azure DevOps' work tree). A
    bare filename or a relative path leaks no structure and passes; an
    absolute path (drive letter or UNC) is the finding, carried as the
    evidence.
    """
    codeview = (metadata.get("debug") or {}).get("codeview") or {}
    pdb_path = str(codeview.get("pdb_path") or "")
    if not pdb_path:
        return True
    if (len(pdb_path) >= 2 and pdb_path[1] == ":") or pdb_path.startswith("\\\\"):
        return pdb_path
    return True


def check_libc_portability(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    # An image that reaches into C library internals is bound to the
    # implementation it was built against, so report the interfaces by name
    # rather than a bare pass or fail.
    abi = metadata.get("abi_analysis") or {}
    names = (abi.get("features") or {}).get("implementation_specific_imports") or []
    if not names:
        return True
    return ", ".join(names[:10])


def check_abi_floor(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
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
) -> bool | str:
    # Libraries opened at runtime are absent from the dependency table, so an
    # image that loads them has a dependency surface no static list describes.
    recovered = metadata.get("recovered_dependencies") or []
    confident = [
        entry["name"] for entry in recovered if entry.get("confidence") in ("high", "medium")
    ]
    if not confident:
        return True
    return ", ".join(sorted(confident)[:10])


def check_link_closure(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
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


def check_search_path(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
    # A search path entry that is relative or world writable lets a directory
    # outside the package decide which library answers first.
    closure = metadata.get("link_closure") or {}
    risky = closure.get("risky_search_paths") or []
    if not risky:
        return True
    return ", ".join(f"{entry['kind']} {entry['path']} ({entry['issue']})" for entry in risky[:5])


def check_unused_dependencies(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    # Only meaningful once symbols can be attributed to libraries; without that
    # every dependency looks unused.
    hygiene = metadata.get("link_hygiene") or {}
    unused = [entry["name"] for entry in hygiene.get("unused_dependencies") or []]
    if not unused:
        return True
    return ", ".join(unused[:10])


def check_undeclared_dependencies(
    f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]
) -> bool | str:
    # A library supplying symbols without being declared is reached through
    # someone else's dependency list, which is not a contract.
    hygiene = metadata.get("link_hygiene") or {}
    undeclared = [entry["name"] for entry in hygiene.get("undeclared_dependencies") or []]
    if not undeclared:
        return True
    return ", ".join(undeclared[:10])


def check_security_property(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool:
    """Fire only on a property that was computed and found False.

    The tristate discipline at the rule layer: a property key absent from
    ``security_properties`` means the source it is computed from was absent
    (P2.4), so there is nothing to claim and the rule stays silent. Reading
    an omitted key as a failure is what made CHECK_ENCLAVE/CHECK_XFG/
    CHECK_CET fire on every file blint could not even parse as a PE (V4).
    """
    properties = metadata.get("security_properties") or {}
    key = rule_obj.get("property_key")
    if not key:
        return True
    value = properties.get(key)
    if value is None:
        return True
    return value is True


def check_packed(f: str, metadata: dict[str, Any], rule_obj: dict[str, Any]) -> bool | str:
    """Flag binaries whose entropy analysis found packing evidence.

    Follows the checks convention: True means clean, a string carries the
    finding detail, and False would mean the rule fired without evidence.
    """
    packing = (metadata.get("entropy") or {}).get("packing") or {}
    likelihood = packing.get("packed_likelihood")
    if likelihood not in ("high", "medium"):
        return True
    packers = packing.get("packers") or []
    findings = packing.get("findings") or []
    detail = ", ".join(packers) if packers else ", ".join(findings[:5])
    return f"packing evidence ({likelihood}): {detail}" if detail else True
