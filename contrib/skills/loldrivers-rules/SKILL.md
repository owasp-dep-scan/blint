---
name: loldrivers-rules
description: Periodically re-measure blint's Windows driver rule coverage against the LOLDrivers corpus and draft candidate rules for the gaps. Use when asked to refresh driver/BYOVD detection coverage, after new vulnerable drivers are published, or on a schedule via /loop.
---

# LOLDrivers rule coverage loop

Re-measures blint's driver rules against the LOLDrivers corpus of known-vulnerable
drivers, then drafts rules for measured gaps. The corpus publishes each sample's
imported function list, so import-based rules can be evaluated at scale without
downloading any binaries.

**This skill never commits and never edits shipped rule files directly.** It
produces a coverage report plus candidate rules in a staging file for a human to
review. A high hit count proves a gap exists, not that a proposed rule is sound.

## 1. Measure

```bash
python contrib/loldrivers/sync_loldrivers.py --report /tmp/blint-loldrivers/coverage.json
```

Add `--dataset <file>` to reuse a local copy instead of refetching, and
`--update-snapshot` once you have finished a pass so the next run reports only
what is new.

Read from the report:

- `rule_hits` — per-rule hit counts. A rule that drops sharply between runs
  usually means a regression in the rule, not a change in the corpus.
- `undetected_count` / `undetected_percent` — samples where no driver rule fires.
- `candidate_imports` — imports ranked by frequency among undetected samples.
  This is the raw material for new rules.

## 2. Decide whether there is a real gap

Group `candidate_imports` into capability clusters by hand before proposing
anything. A cluster is rule-worthy when the imports co-occur and together grant a
single coherent primitive. For example `ZwOpenProcess` + `PsLookupProcessByProcessId`
+ `KeStackAttachProcess` + `ObOpenObjectByPointer` is a cross-process
memory/handle primitive; that is one rule, not four.

Reject a cluster when:

- The imports are ubiquitous plumbing (locks, string helpers, pool allocation).
  Extend `UNINTERESTING_IMPORTS` in the sync script instead.
- An existing rule already covers the capability under a different name. Check
  `blint/data/annotations/review_imports_pe.yml` and `review_drivers_win.yml`
  first — overlapping rules inflate apparent coverage without adding signal.
- The capability is normal for the driver class in question. Filesystem and
  network filter drivers legitimately import alarming-looking APIs.

## 3. Draft the rule

Delegate drafting of each accepted cluster to a subagent, one agent per cluster,
so the drafts stay independent. Give the agent: the cluster's imports, their
undetected-sample counts, and the instruction to match the existing rule style in
`blint/data/annotations/review_drivers_win.yml`.

Every rule needs an `id`, `title`, `summary`, `description` and `check_type`.
Requirements for the description, which is what a reviewer actually reads:

- State the primitive the imports grant and why it matters in kernel context.
- Name a concrete driver or CVE that exhibits it, when the corpus entry has one
  (`Category`, `Tags` and the loldrivers `Resources` field are the sources).
- State the legitimate uses that will cause false positives. Every rule in this
  area fires on benign vendor drivers; say so rather than implying certainty.

Write drafts to `contrib/loldrivers/candidate-rules.yml`, never to the shipped
annotation files.

Prefer an `IMPORT_REVIEWS` rule when a set of import names is sufficient. Use a
`BINARY_REVIEWS` rule with `check_type: binary_analysis` when the signal depends
on a *combination* or on the *absence* of something, since import pattern rules
cannot express either; that needs a matching branch in
`_evaluate_binary_analysis` in `blint/lib/binary_reviews.py`.

## 4. Verify before proposing

A draft is not a candidate until all of these hold:

```bash
# Rules parse and load into the expected group
python -c "import yaml; list(yaml.safe_load_all(open('contrib/loldrivers/candidate-rules.yml')))"
# Nothing already shipped regressed
python -m pytest tests/test_driver_ioctl.py tests/test_analysis.py -q
# Coverage actually improved, and by how much
python contrib/loldrivers/sync_loldrivers.py --dataset <local copy> --report /tmp/after.json
```

Load the candidate file with `--custom-rules-dir` (or copy it into a scratch
annotations directory) when re-measuring, and report the before/after
`undetected_percent`. A candidate rule that does not move that number is not
worth shipping.

Then report to the user: the coverage delta, each proposed rule with its cluster
evidence, and the false-positive exposure you could not rule out. Note explicitly
that the corpus contains only known-vulnerable drivers, so it measures recall
only — it says nothing about how often a rule fires on benign drivers. Claims
about precision need a separate corpus of legitimate signed drivers.

## Scheduling

To run this periodically:

```
/loop 168h /loldrivers-rules
```

Weekly matches the corpus's rate of change; daily mostly re-reports the same
gaps. Use `--update-snapshot` at the end of a pass so subsequent runs surface
newly published drivers rather than the whole corpus.
