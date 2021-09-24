import yaml
import os
import sys
import json

from pathlib import Path


from rich.progress import Progress

from blint.binary import parse
from blint.utils import find_exe_files
from blint.logger import LOG

rules_file = Path(__file__).parent / "rules.yml"
rules_dict = {}
with open(rules_file) as fp:
    raw_data = fp.read().split("---")
    for tmp_data in raw_data:
        rules_list = yaml.safe_load(tmp_data)
        for rule in rules_list:
            rules_dict[rule.get("id")] = rule


def check_nx(f, metadata):
    if metadata.get("has_nx") is False:
        return False
    return True


def check_pie(f, metadata):
    if metadata.get("is_pie") is False:
        return False
    return True


def run_checks(f, metadata):
    results = {}
    if not rules_dict:
        LOG.warn("No rules loaded!")
        return None
    if not metadata:
        return None
    for cid, rule_obj in rules_dict.items():
        cfn = getattr(sys.modules[__name__], cid.lower(), None)
        if cfn:
            result = cfn(f, metadata)
            if not result:
                rule_obj["filename"] = f
                if metadata.get("name"):
                    rule_obj["exe_name"] = metadata.get("name")
                results[cid] = rule_obj
    return results


def start(args, src, report_file):
    files = [src]
    findings = []
    if os.path.isdir(src):
        files = find_exe_files(src)
    with Progress(
        transient=True,
        redirect_stderr=False,
        redirect_stdout=False,
        refresh_per_second=1,
    ) as progress:
        task = progress.add_task(
            f"[green] Scan {len(files)} binaries",
            total=len(files),
            start=True,
        )
        for f in files:
            progress.update(task, description=f"Processing [bold]{f}[/bold]")
            metadata = parse(f)
            with open("out.json", mode="w") as fp:
                json.dump(metadata, fp, indent=True)
            finding = run_checks(f, metadata)
            if finding:
                findings.append(finding)
    return findings
