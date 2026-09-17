# Lessons from building blint v4

blint v4 added the analysis engine, the Apple depth work, the blintdb hash
layers, `blint diff`, and the Python API. Most of what follows was learned
from a failure that CI or a verification gate caught, sometimes weeks after
the code first looked correct. Each lesson names the code it now lives in,
so this file doubles as a map of the sharp edges.

## Validate the input before handing it to a parser

LIEF is tolerant to a fault. A directory path or a device file handed to it
does not reliably raise; it can come back as a parse result that is nearly
empty, and a nearly empty parse looks exactly like a total analysis
regression downstream. The gates now refuse a non-file input before LIEF
sees it, and they exit with a distinct status (2) so an unusable input is
never confused with a failing verdict. The same trap exists inside the test
suite: `parse()` on a path that does not exist returns near-empty metadata
instead of raising, so a mistyped fixture path reads like the callgraph
collapsed. `functions_total` being zero is the tell. Check it before
believing any comparison.

A related fixture lesson: the Mach-O address-space tests ran for months
against an ELF on Linux, because the fixture was named as if it were a
Mach-O and nothing asserted the format. Tests that guard a format should
assert the format first.

## Trust the structured form, not the flattened one

Go buildinfo is a framed blob, not text. Reading module and path from
flattened strings worked until a binary appeared whose framing put those
fields where the flattened view could not recover them, and the toolchain
version had to be read from the raw blob for the same reason. Whenever a
format gives you a structured and a stringly form of the same information,
read the structured one.

Ordering is the other half of this lesson. PE `dynamic_entries` was
assembled from a Python set, so its order was hash-seeded and two runs over
the same bytes produced different JSON. Anything that reaches an output file
must come from a deterministic ordering step, and the determinism gate runs
under two `PYTHONHASHSEED` values precisely so this class of bug cannot
land quietly.

## A fat binary is several binaries

`lief.parse` auto-selects one slice of a Mach-O universal binary. Code that
asked it for "the binary" was silently answering for one architecture:
`/usr/bin/git` carries PAC on its arm64e slice only, so the top-level
summary read exactly like a binary that was checked and found to lack it.
The fix has two parts. Every slice is analyzed through the `FatBinary`, and
the summary says so in band: `security_properties_scope` marks the answer
as the primary slice's, and `security_properties_slice_variance` names each
property the slices disagree about. Nothing is merged, because a merge
would have to choose between an optimistic and a pessimistic lie.

Mach-O address spaces caused the same class of surprise for functions.
lief's aggregate function list mixes file-offset and virtual-address
entries, and `sub_<addr>` names keyed on the wrong space collide. Function
metadata is now normalized into one virtual address space, with entries the
segment ranges cannot place left in their raw space and counted as
ambiguous rather than guessed at. A nameless or repeated symbol in that
walk is not a second function; treat it as noise.

## Record what the analysis could not do

The most useful v4 habit is writing the blind spot into the metadata
instead of leaving the consumer to discover it. The call-site argument block
ships a `call_site_arguments_coverage` record; the top level carries an
`analysis_degradations` list that mirrors it, plus the Mach-O address-space
ambiguities, so a consumer reading only the summary still sees what was
unresolved and why. Two rules of thumb came out of the abstract
interpreter work: a narrow write cannot carry a materialised pointer, and a
partial block read is worse than no read (the CreateFile path argument was
wrong until the block was required to be complete before decoding). When a
heuristic cannot decide, emit the degradation; do not emit a guess.

The same discipline applies to rule authorship. CHECK_CANARY could never
fire on an ELF because the rule read a Windows-only evidence path: a rule
that can never fire passes every test that only checks it does not crash.
Negative-path tests, an explicit PE `has_canary` verdict, and fixture names
that state their format are the antidote.

## Do not encode what you cannot verify

An early Objective-C metadata reader emitted relative-method encodings for
layouts it had not actually decoded. The output looked richer and was
silently fabricated. Those invented encodings were removed and three unsafe
reads were guarded instead. On Apple platforms specifically: walk
`Contents/Library` recursively (frameworks nest), gate helper files on the
Mach-O magic rather than an extension, and never let a test depend on a
symlink-dependent spelling of a framework path.

## Forking a threaded parent deadlocks

The `--jobs` pool forked a process that had already started threads
(progress bars, rich), and CI sat on the deadlock until the run timed out.
The fix moved pool creation ahead of any thread start. Two neighboring
lessons: Windows needs a portable hard-kill signal to actually test worker
teardown, and a byte-equality gate across `--jobs 1/2/4/8` must normalize
the SBOM timestamp before comparing, or it fails for a reason that is not
the thing being gated.

The parse cache learned the same lesson about time and schema. Entries
written by an older schema must not be served to a newer reader, so the
schema version is bumped whenever parse output changes for unchanged
inputs, and a worker that opened the store before its schema existed could
silently lose a row, so open paths check what they are reading. Parses
without a recognized `binary_type` are not cached at all: caching a
microsecond near-nothing pollutes the store without saving anything.

## Gates must fail for the right reason

A verification gate that compares against an external oracle is worth
several that compare against blint itself: the code-signature tests assert
against `codesign` output, and the pointer-precision gate against
`llvm-objdump` and the image bytes. When an oracle sweeps line by line, a
derailment must not be trusted past the entry where it crossed, because
every comparison after the crossing is also wrong and half of them will
look like passes. And because comparison logic only flags counters that
drop, a baseline recorded from a weaker run keeps passing while losing its
ability to catch anything; refresh baselines when output legitimately
grows, not only when they fail.

## Matching judgements stay per-candidate

The recurring blintdb lesson, first learned in d6237a5 and restated for
every layer since: a per-candidate judgement must not travel through a
lookup-wide flag. Member-level static-archive evidence may waive a filter
for the candidate it belongs to, never for the whole lookup, or unrelated
projects start matching on evidence they do not have. The same conservatism
drives the layer design: exact project evidence first, fuzzy similarity
hashes only as a recorded degradation, and false positives treated as more
expensive than missed low-confidence hints, because a wrong component in an
SBOM is reviewed by a human who cannot tell it from a right one.

## Structure survives, scratch does not

`binary.py` grew to 5568 lines before it was split by format into the
`binary_*.py` readers with every old importable name re-exported. The split
was safe because the public surface was preserved, and it made the
per-format lessons above easier to see in the first place. What did not
survive: the scratch A/B scripts used during development, removed as soon
as the answer they were built to check landed in a real gate. If a
measurement is worth keeping, it is worth keeping as a named script under
`tests/scripts/` with a row in that directory's README; otherwise it is
clutter with a shelf life.
