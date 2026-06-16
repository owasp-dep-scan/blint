# Callgraph matching in blint

## What this feature does

blint can take a callgraph produced from source code and compare it against the
callgraph it recovers from a compiled binary. The goal is to decide which
functions in the binary correspond to which functions in the source, and to do
this even when the binary has been stripped of some or all of its symbols.

Does it work? Yes, with an important nuance. The part that matches functions by
name works very well and is reliable. On the wasm-tools 1.247.0 Linux binary it
identifies a little over four thousand functions with high confidence and maps
them back to specific Rust source functions. The part that tries to recover
function identities purely from call structure, used when names are missing, is
much weaker on real Rust release binaries. The reason is explained in the
limitations section: most of the missing call edges come from dynamic dispatch
that cannot be resolved without runtime information. So the honest summary is
that name based identification is production quality today, and structure based
recovery is a best effort signal that should be reviewed rather than trusted
blindly.

## The inputs

There are two callgraphs involved.

The source callgraph comes from a source analysis tool. The current work uses
rusi for Rust. Its nodes are fully qualified function names such as
`wasmparser::validator::operators::OperatorValidator::new_func`, and its edges
are calls between them. Every node also carries a package URL so a match can be
attributed to a specific crate and version.

The binary callgraph comes from blint itself. When blint disassembles a binary
it records each function, the calls it makes, and a set of per function
properties such as instruction count and whether the function contains a loop, a
system call, or a cryptographic call. blint already demangles Rust and C++
symbol names when they are present, so a function in the binary callgraph is
usually labelled with a readable name rather than a mangled one.

## The core idea: a shared canonical name

Source tools and disassemblers spell the same function slightly differently. A
method might appear in the source as
`OperatorValidatorTemp<R>::label_types` and in the binary as
`<wasmparser::...::OperatorValidatorTemp<R> as ...>::label_types` followed by a
compiler hash. To compare the two graphs, blint reduces every name on both sides
to a canonical form. Canonicalization removes compiler hash suffixes, lifetimes,
generic arguments, and trait qualifier wrappers, and it collapses every
monomorphized copy of a generic function back onto the single source definition
it came from. The result is a stable name of the shape
`crate::module::Type::method` that both sides can agree on.

This logic lives in `blint/lib/callgraph/canon.py`. Raw mangled symbols, when
they do appear, are demangled first using the multi-demangle library, which
handles Rust v0 and legacy mangling as well as C++ and Swift. Keeping all of the
naming rules in blint means the database and the matcher always join on an
already canonical key, and it means the approach extends to other languages
without changing the matcher.

## The matching algorithm

The matcher works in layers of decreasing certainty. Each layer only attempts
functions that earlier layers left unmatched.

Layer 0 is anchoring. A binary function whose canonical name equals a source
canonical name is matched directly. These matches are marked high confidence.
On an unstripped binary this recovers the large, trustworthy backbone of the
result, and it also serves as the ground truth used to test the harder layers.

Layer 1 is structural propagation. Starting from the anchors, an unmatched
binary function is matched to the source function that occupies the same
position in the call structure. Concretely, if the callers and callees of a
binary function have already been matched, the source function that shares those
same callers and callees is the natural candidate. A function is only accepted
when enough already matched neighbors agree and the best candidate leads the
runner up by a margin. These matches are marked medium or low confidence.

Layer 2 is structural fingerprinting. It widens Layer 1 from immediate neighbors
to a small radius of hops and scores candidates by how well their neighbor name
sets overlap, using the per function disassembly properties to avoid matching
trivial stubs against substantial functions. Layer 2 is turned off by default
because on edge sparse binaries it tends to add a few correct matches at the
cost of many uncertain ones. It is available for callgraphs that are densely
resolved, and it helps in specific cases such as a function that sits behind an
inlined wrapper.

The matcher produces a many to one mapping, since a single generic source
function can be compiled into several specialized binary functions. The code for
all of this is in `blint/lib/callgraph/match.py`, the graph model is in
`model.py`, and the fingerprint helpers are in `fingerprint.py`.

## Choosing an algorithm

The matching strategy is pluggable. The registry in
`blint/lib/callgraph/algorithms.py` currently offers two strategies. The
`layered` strategy is the general purpose default and runs anchoring, then
propagation, and optionally fingerprinting. The `anchors` strategy runs name
matching only, which is the fastest and highest precision option and is useful
for plain identification of an unstripped binary. New strategies can be
registered without touching the loaders, the report format, or the command line.

## Running it

The command is `blint callgraph-match`. It needs a source callgraph and a
binary. The binary can be supplied as a path to a binary, in which case blint
disassembles it, or as a path to a previously generated blint metadata file.

A typical run looks like this:

```
blint callgraph-match \
  --source path/to/callgraph.json \
  --binary-metadata path/to/wasm-tools-metadata.json \
  --output match-report.json
```

The configuration options are as follows.

`--algorithm` selects the strategy, either `layered` or `anchors`. The default
is `layered`.

`--min-confidence` filters which matches are listed in the report, one of `low`,
`medium`, or `high`. The summary counts always reflect every match regardless of
this filter.

`--no-propagation` turns off Layer 1 and reports only name anchors.

`--with-fingerprint` turns on the experimental Layer 2 fingerprinting.

`--min-votes` and `--margin` control Layer 1. `--min-votes` is the number of
agreeing matched neighbors required to accept a match, default two.  `--margin`
is how far the best candidate must lead the runner up, default one.

`--khop`, `--fp-min-shared`, `--fp-min-score`, and `--fp-margin` control Layer 2.
They set the neighbor radius, the minimum number of shared neighbor names, the
minimum overlap score, and the minimum lead over the runner up. The defaults are
two, two, 0.34, and 0.1, chosen to favor precision.

`--output` writes the full machine readable report as JSON. The report contains
the summary counters, the chosen algorithm, and the list of individual matches
with their address, source function, confidence, matching method, and evidence
type.

## The console output

Without the quiet flag the command prints a readable summary. It opens with a
short verdict in plain language, for example a statement that several thousand
functions matched by name and the binary is consistent with the provided source.
It then shows an overview of the counts, a breakdown of how functions were
matched and at what confidence, and an evidence table of representative matches
with their addresses and source names. The evidence table deliberately mixes the
different matching methods so that name anchors and structural matches are both
visible. The output closes with a note explaining why many functions are
expected to remain unmatched and reminding the reader that structural matches are
lower confidence than name anchors. The quiet flag suppresses all of this for
scripted use.

## Storing callgraphs for corpus scale matching

Matching one binary against one source graph is useful, but the more powerful
use case is matching an unknown binary against many known source graphs at once.
The blint-db project supports this. Its schema gained three additive tables,
`SourceGraphs`, `CallGraphNodes`, and `CallGraphEdges`, with a discriminator that
marks each graph as either source or binary. Ingesting a binary now also stores
its callgraph, and a new function ingests a source callgraph and registers it
against a project and package URL. A query then ranks the stored source graphs by
how many canonical function names they share with a given binary. In testing,
an unknown wasm-tools binary was correctly identified as
`pkg:cargo/wasm-tools@1.247.0` by this overlap, with several thousand shared
functions, while an unrelated decoy source graph was correctly excluded.

## Testing methodology

There are two kinds of tests.

The unit tests cover canonicalization against real name pairs taken from the
wasm-tools binary and source, the graph loaders, the matcher layers on small
constructed graphs, the fingerprint mechanics, and the algorithm registry. They
run as part of the normal blint test suite. The blint-db tests cover the new
schema, ingestion, and the corpus matching query.

The accuracy of the matcher is measured by a separate experiment that does not
rely on hand labelling. The script
`tests/scripts/callgraph_match_kpi.py` takes the unstripped binary, computes the
name based matches, and treats them as ground truth. It then deterministically
hides a chosen fraction of the function names, which simulates a partially
stripped binary, and runs the matcher again. It scores how well the structural
layers recover the hidden mappings using precision and recall against the ground
truth. The selection of which names to hide is driven by a stable hash of the
function address, so the experiment is fully reproducible. Baselines are stored
per platform in the same style as the existing callgraph KPI baselines, so
accuracy drift can be caught over time.

## Limitations and honest results

The name based layer is strong. The structural layers are limited by how many
call edges blint can recover from the binary. On the wasm-tools Linux binary the
recovered callgraph has roughly as many edges as nodes, and around seventy five
thousand additional calls could not be resolved at all. The vast majority of
these are indirect calls, which in Rust means dynamic dispatch through trait
object vtables and calls through function pointers held in registers or on the
heap. The target of such a call is only known at runtime, so it cannot be
resolved by static disassembly with any precision.

This was investigated directly. The binary does contain about seventeen thousand
relocation slots that point at real functions, which are the vtables and
function pointer tables. A resolver was built to follow an indirect call through
a statically known slot to its concrete target. It is precise, but it recovered
almost no new edges, because the dispatch sites load the vtable pointer from
runtime data rather than from a fixed address, so the slot being used is not
known at the call site. Resolving those calls would require value set or points
to analysis, which is expensive and tends to be imprecise, so it was not
pursued. The change was reverted to keep the disassembler and its regression
baselines stable.

The practical conclusion is that for stripped Rust binaries the matcher recovers
the functions whose names survive and a modest number of additional functions by
structure, and that recovering the rest would need analysis techniques beyond
static disassembly. For unstripped binaries, and for the common task of
identifying which source project and version a binary was built from, the
matcher already works well.

## Where the code lives

The matcher and its pieces are under `blint/lib/callgraph/`. Canonicalization is
in `canon.py`, the graph model and loaders in `model.py`, the matcher and report
builder in `match.py`, the fingerprint helpers in `fingerprint.py`, the algorithm
registry in `algorithms.py`, and the command orchestration and console rendering
in `command.py`. The validation script is `tests/scripts/callgraph_match_kpi.py`.
The corpus storage and queries are in the blint-db project under
`blint_db/handlers/`.
