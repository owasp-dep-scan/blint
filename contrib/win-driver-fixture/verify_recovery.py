#!/usr/bin/env python3
"""Check blint's driver analysis against a driver whose IOCTLs are known.

Run this on the .sys produced by build.cmd. The control codes are ground truth
declared in ioctl_driver.c, so a failure here means blint's recovery is wrong,
not that the expectation drifted.

    python contrib/win-driver-fixture/verify_recovery.py blint_test_driver.sys

Exit status is 0 when every required expectation holds. The switch and table
groups are reported but not required: whether the compiler emits a jump table or
a compare chain for a given switch is its own choice, and asserting on one
particular lowering would make this a test of MSVC's optimizer rather than of
blint. What is required is that no code in those groups is ever *wrong*.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from blint.config import BlintOptions  # noqa: E402
from blint.lib.analysis import initialize_rules  # noqa: E402
from blint.lib.binary import parse  # noqa: E402
from blint.lib.review_runner import ReviewRunner  # noqa: E402

# Ground truth, mirroring the CTL_CODE values in ioctl_driver.c.
COMPARE_CODES = {0x80002400, 0x80002954, 0x80003444}
NEITHER_CODE = 0x800039F3
SWITCH_CODES = {0x80002440 + step * 4 for step in range(16)}
TABLE_CODES = {0x80002480, 0x80002484, 0x80002488, 0x8000248C}
ALL_DECLARED = COMPARE_CODES | {NEITHER_CODE} | SWITCH_CODES | TABLE_CODES

REQUIRED_RULES = {
    "DRIVER_INSECURE_DEVICE_OBJECT",
    "DRIVER_IOCTL_METHOD_NEITHER",
}

EXPECTED_DEVICE_NAME = "\\Device\\BlintTestDriver"
EXPECTED_SYMLINK = "\\DosDevices\\BlintTestDriver"


def check(results: list, ok: bool, required: bool, label: str, detail: str = "") -> None:
    """Record one expectation."""
    results.append({"ok": ok, "required": required, "label": label, "detail": detail})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("driver", help="path to the built .sys fixture")
    args = parser.parse_args()

    initialize_rules(BlintOptions())
    metadata = parse(args.driver, disassemble=True)

    if not metadata.get("disassembled_functions"):
        print("FAIL: nothing was disassembled; is the nyxstone extra installed?")
        return 2

    driver_ioctls = metadata.get("driver_ioctls") or {}
    recovered = {int(entry["code"], 16) for entry in driver_ioctls.get("ioctls", [])}
    interface = metadata.get("driver_interface") or {}

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    fired = {result["id"] for result in reviewer.process_review(args.driver, args.driver)}

    results = []

    check(
        results,
        bool(driver_ioctls.get("dispatch_handlers")),
        True,
        "IRP_MJ_DEVICE_CONTROL dispatch slot store located",
    )
    check(
        results,
        COMPARE_CODES <= recovered,
        True,
        "compare-chain control codes recovered",
        f"missing {sorted(hex(c) for c in COMPARE_CODES - recovered)}",
    )
    check(
        results,
        NEITHER_CODE in recovered,
        True,
        "METHOD_NEITHER control code recovered",
    )
    check(
        results,
        EXPECTED_DEVICE_NAME in (interface.get("device_names") or []),
        True,
        "device name recovered from UTF-16 strings",
        f"got {interface.get('device_names')}",
    )
    check(
        results,
        EXPECTED_SYMLINK in (interface.get("symbolic_links") or []),
        True,
        "symbolic link recovered from UTF-16 strings",
        f"got {interface.get('symbolic_links')}",
    )
    for rule_id in sorted(REQUIRED_RULES):
        check(results, rule_id in fired, True, f"{rule_id} fired")

    # A recovered code that was never declared is a false positive, and unlike a
    # missed lowering that is always blint's fault.
    spurious = recovered - ALL_DECLARED
    check(
        results,
        not spurious,
        True,
        "no control codes recovered that the driver does not declare",
        f"spurious {sorted(hex(c) for c in spurious)}",
    )

    check(
        results,
        SWITCH_CODES <= recovered,
        False,
        "switch jump-table cases recovered",
        f"{len(SWITCH_CODES & recovered)}/{len(SWITCH_CODES)} cases",
    )
    check(
        results,
        TABLE_CODES <= recovered,
        False,
        "data-section dispatch table recovered",
        f"{len(TABLE_CODES & recovered)}/{len(TABLE_CODES)} entries",
    )

    failed = 0
    for result in results:
        if result["ok"]:
            status = "PASS"
        elif result["required"]:
            status = "FAIL"
            failed += 1
        else:
            status = "MISS"
        line = f"{status}: {result['label']}"
        if not result["ok"] and result["detail"]:
            line += f" ({result['detail']})"
        print(line)

    print(f"\nrecovered {len(recovered)} control codes: {sorted(hex(c) for c in recovered)}")
    print(f"rules fired: {sorted(fired)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
