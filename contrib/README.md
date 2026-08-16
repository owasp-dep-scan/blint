# contrib

Optional tooling that is not part of the blint package. Nothing here is imported
by blint at runtime, and nothing here runs during a normal scan.

## `loldrivers/`

`sync_loldrivers.py` measures blint's Windows driver rule coverage against the
[LOLDrivers](https://www.loldrivers.io) corpus of known-vulnerable drivers. The
dataset publishes each sample's imported function list, which is enough to
evaluate blint's import-based driver rules across thousands of real vulnerable
drivers without downloading any binaries.

```bash
python contrib/loldrivers/sync_loldrivers.py --report /tmp/coverage.json
```

It reports per-rule hit counts, the share of samples no rule detects, and the
imports most common among those undetected samples, which is where new rules
should come from.

Two limits worth keeping in mind when reading its output:

- The corpus contains only known-vulnerable drivers, so it measures **recall
  only**. It cannot tell you how often a rule fires on a benign driver; that
  needs a separate corpus of legitimate signed drivers.
- Import lists cannot exercise rules that depend on disassembly, such as the
  IOCTL surface recovery or the instruction-level MSR and port I/O rules.

## `win-driver-fixture/`

A driver-shaped PE whose IOCTL surface is known ahead of time, plus the scripts
that check blint's recovery against it. It covers what the LOLDrivers harness
cannot: the disassembly-dependent analysis, which needs a binary rather than an
import list. `inbox_sweep.py` complements it from the other side, measuring how
often the driver rules fire on the signed Microsoft drivers already installed on
a Windows machine - the precision half of the question LOLDrivers cannot answer.

See `win-driver-fixture/README.md`. Both run in
`.github/workflows/drivertests.yml`.

## `skills/`

Claude Code skills. `loldrivers-rules` drives the coverage script on a schedule,
groups uncovered imports into capability clusters, and drafts candidate rules
into `contrib/loldrivers/candidate-rules.yml` for human review. It does not edit
shipped rule files and does not commit.
