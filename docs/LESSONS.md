# Lessons from building blint v4

blint v4 added the analysis engine, the Apple depth work, the blintdb hash
layers, `blint diff`, and the Python API, then Windows depth (Authenticode
and catalogs, .NET metadata, Windows containers and Office documents,
drivers), a false-positive sweep over ELF and Mach-O, and Android native
code (per-ABI facts and rules, framework identification, the dex↔native
JNI join). Most of what follows was learned from a failure that CI, a
verification gate or a review caught, sometimes weeks after the code first
looked correct. Each lesson names the code it now lives in, so this file
doubles as a map of the sharp edges.

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

Saying what was not done applies to trust as much as to coverage. The PE
`code_signature` block names a signer chain and states
`trust_validation: "not_performed"`, so no consumer reads "signed" as
"trusted"; without `--catalog-dir`, a file with no embedded signature
carries `catalog_lookup: "not_performed"` instead of reading as unsigned,
which is what most of `C:\Windows\System32` would otherwise be. And a
placeholder is not a finding: a call-site rule that could not run on an ABI
once emitted `not_evaluated` evidence, and because any non-empty evidence
becomes a review row, the placeholder shipped as a detection. It now goes
to `analysis_coverage` as a named degradation (`callsite_abi_not_modelled`).

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

## Never match on a rendered enum

LIEF 1.0 changed how it renders `DLL_CHARACTERISTICS`: flags that used to
print as names printed as integers. Every check that searched the rendered
text for `DYNAMIC_BASE` quietly stopped matching, so `aslr` read false on
every PE and `CHECK_DLL_CHARACTERISTICS` fired at high severity on
hardened, Microsoft-signed binaries. Nothing crashed and every test that
only checked for a result kept passing. Rules and facts now read the
numeric value and name the flags themselves (`blint/lib/pe_kernel_posture.py`
restates the values it needs as named constants), and a rule that only
means something on some machines says so: the `machine_types` gate in
`blint/lib/analysis.py` reads the numeric machine type, which is what keeps
ARM pointer-authentication checks off x86-64 binaries.

The same release showed the cost of judging bytes before knowing what they
are. The Authenticode signature sits after the last section, so it was
counted as an overlay and fed the packing heuristic. `blint/lib/pe_overlay.py`
now subtracts the security directory before it classifies the residue.

## Untrusted containers need bounds you can cross

Every archive blint opens (MSIX and Appx, MSI and CFBF, CAB, 7z
self-extractors, NuGet packages, OOXML) is untrusted input, and each reader
in `blint/lib/container.py` and its siblings carries caps on member count,
total size and nesting. A cap counts only if a fixture crosses it: a bound
that no test reaches is a guess, not a bound. Cleanup is asserted the same
way. The NuGet tests snapshot the live temp directory before and after a
parse and require an empty delta across success and every refusal, which
is stronger than checking that the code calls `rmtree`.

Unknown is reported as unknown. A NativeAOT image has no CLI header, yet it
must never read as "not .NET"; a file with no evidence of any publish shape
gets no shape block, which is silence rather than a native verdict
(`blint/lib/pe_dotnet_shape.py`). A driver kind the evidence does not
establish is `"unknown"`, never `"wdm"` by default
(`blint/data/pe_driver_kinds.yml`). A negative that was never measured is a
false positive waiting for a consumer.

## Calibrate at real scale, on real shapes

The false-positive sweep's defects shared one cause: a rule tuned on small
inputs that was wrong at production scale or on a shape the samples did
not have. Suppressing symbol names that several blintdb projects share
looked like pure noise reduction on a small database; at production size
it removed zlib's own identity from libz. Shared names now only stop
counting toward a match that has no binary-name agreement. Version banners
were demoted to mentions in any dynamic artifact that defined no API
symbols, which demoted exactly the stripped, hidden-visibility vendored
copies Android apps ship.

The Android work added two cheap checks that catch this class. Rebuild the
positive fixture at `-O0`, `-Os`, `-Oz`, with LTO and with an older NDK
before trusting a filter: a filter that treated conditional returns as
terminators dropped real `svc` sites on three of four builds. And measure
on the inputs the code will meet, not on the KPI fixtures: LIEF reports
wrapped 64-bit function sizes on stripped C++ libraries, the disassembler
trusted them and decoded to the end of `.text` (a 1.3 MB `libc++_shared.so`
produced 1.77 GB of metadata), and the KPI binaries never showed it because
each had one function. blint's own unwind-based discovery had the right
sizes all along.

## Linking a framework is not being it

A library that statically links BoringSSL is not BoringSSL, and a file name
is a hint, not an identity. The first Android framework identifier replaced
the identity of AOSP's NNAPI sample driver with BoringSSL because the
driver re-exports `BORINGSSL_self_test`. The structural test is the
`DT_SONAME`: a framework replaces a library's identity only when the
library's own SONAME is one of the project's library names
(`blint/lib/framework_ident.py`, `blint/lib/android_blintdb.py`); otherwise
the match nests as a statically linked child. Versions come from the
artifact, never from the database row, which records the packaging port's
version rather than the bundled one (OsmAnd ships PROJ 8.2.0 while the
port row says 9.8.1), and a linked library's version is never the
artifact's own.

## One answer per ABI

An Android app ships the same library once per ABI, and each copy is a
different binary. Every fact, rule and JNI row is computed from that ABI's
own copy; a missing copy answers nothing for its ABI rather than borrowing
another ABI's bytes, and a list never collapses to the first or best ABI.
The ABIs also disagree about addresses: arm32 dynamic symbols carry the
Thumb bit in bit 0, while x86 code legitimately starts at odd addresses, so
an oracle that masks bit 0 on every ABI fails hundreds of correct x86 rows.
A rule that cannot apply to an ABI does not run on it: 32-bit ABIs are
exempt from the 16 KB page rule and never flagged.

Severity follows the context too. The Play 16 KB requirement binds apps
that target API 35 or later, so the rule is high for such an app, silent
for an older target, and medium for a standalone system library that no
known app ships. `CHECK_ABI_FLOOR` is `info` against the built-in glibc
baseline and `medium` only against one the user set, and the arm64 BTI/PAC
posture check is `low` because almost every NDK build lacks it.

## Evidence must name what the runtime acts on

A `RegisterNatives` table carries a method name, a signature and a
function pointer, but no class. Matching it to dex declarations by name and
signature is a binding only when exactly one class declares that pair;
fennec declares `disposeNative` with the same signature eleven times, so
those rows stay `ambiguous_dynamic` until the registering function's
`FindClass` names the class. A validation that counts a name-and-signature
match as correct cannot find this error, because it checks the rule against
itself.

JNA direct mapping repeated the lesson. `Native.register` binds the natives
of the class the call names, not of the class that makes the call, so a
class whose static initializer merely calls another class's registrar is
not registered. The library name counts only when one constant holds on
every path to the call: arguments are read through the flow-sensitive
`blint/lib/dalvik_dataflow.analyze`, because a linear "last write before
the call" walk keeps a constant after its register was overwritten. And a
capped listing is for output only: the JNI callgraph edges once read the
256-row metadata listing, so every row past the cap had no edge. Code that
consumes the join reads the full join or its counts.

## A green suite proves only what it can fail on

The Windows work ended with more than thirty defects that a fully green
suite had not found, and almost all had one shape: a claim the report
made and the docstring stated, which no test in the repository could
reach. The false-positive sweep found the same shape in smaller forms: an
assertion ending in `or True`, a test that cleared the strings it was meant
to check and so hid a duplicate banner, a docstring that contradicted its
own test. Two habits counter it. A new rule ships with the fixture that
fails without it, run against the old code before the fix lands. And a
reviewer measures independently, with a different tool where one exists
(`llvm-nm`, `llvm-readelf`, `dexdump`, `codesign`), rather than re-running
the author's gate.

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
